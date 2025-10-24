# app/controllers/auth/sessions_controller.rb
class Auth::SessionsController < ApplicationController
  # API用途想定：CSRFは無効（必要に応じてアプリ基盤側で設定済みでOK）
  # protect_from_forgery with: :null_session

  # POST /auth/login
  # params: { email:, password: }
  def create
    # ===================== DEBUG_START:auth_flow =====================
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    req_id  = request.request_id || request.headers["X-Request-ID"]
    Rails.logger.info({ at: "auth.login.start", request_id: req_id }.to_json)
    # ===================== DEBUG_END:auth_flow =======================

    user = User.find_for_authentication(email: params[:email])
    unless user&.valid_password?(params[:password])
      # 認証失敗
      return render json: { ok: false, error: "invalid_credentials" }, status: :unauthorized
    end

    # ===================== HYBRID_START:issue_pair =====================
    svc = RefreshTokenService.new(user: user)
    access_jwt, refresh_raw = svc.issue_pair!
    # ===================== HYBRID_END:issue_pair =======================

    # ===================== HYBRID_START:cookie_set =====================
    cookies[:auth_token] = cookie_options_for_access.merge(value: access_jwt)
    cookies[:refresh_token] = cookie_options_for_refresh.merge(value: refresh_raw)
    # ===================== HYBRID_END:cookie_set =======================

    # ===================== DEBUG_START:auth_flow =====================
    Rails.logger.info({
      at: "auth.login.done",
      request_id: req_id,
      dur_ms: ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
    }.to_json)
    # ===================== DEBUG_END:auth_flow =======================

    render json: { ok: true, user: { id: user.id, name: user.name, email: user.email } }
  rescue => e
    Rails.logger.error({ at: "auth.login.error", err: e.class.name, msg: e.message }.to_json)
    render json: { ok: false, error: "login_internal_error" }, status: :internal_server_error
  end

  # POST /auth/sign_out  （任意：ルーティングでPOST/DELETEどちらでも）
  # - 現在の refresh_token を失効（あれば）
  # - クライアント側Cookieを削除
  def sign_out
    raw = cookies[:refresh_token]
    if raw.present?
      # ===================== HYBRID_START:revoke_current =====================
      user = current_user_from_auth_cookie
      RefreshTokenService.new(user: (user || User.new)).revoke!(raw) rescue nil
      # ===================== HYBRID_END:revoke_current =======================
    end

    # ===================== HYBRID_START:cookie_clear =====================
    cookies.delete(:auth_token,   cookie_delete_options)
    cookies.delete(:refresh_token, cookie_delete_options)
    # ===================== HYBRID_END:cookie_clear =======================

    head :no_content
  end

  # POST /auth/revoke_all  （要認証：auth_token を検証）
  # - ユーザーの全 refresh_token を失効（全端末ログアウト）
  def revoke_all
    user = current_user_from_auth_cookie
    return render json: { ok: false, error: "unauthorized" }, status: :unauthorized if user.nil?

    # ===================== HYBRID_START:revoke_all =====================
    RefreshTokenService.new(user: user).revoke_all!
    # ===================== HYBRID_END:revoke_all =======================

    # クライアントのCookieも削除
    cookies.delete(:auth_token,   cookie_delete_options)
    cookies.delete(:refresh_token, cookie_delete_options)

    head :no_content
  rescue => e
    Rails.logger.error({ at: "auth.revoke_all.error", err: e.class.name, msg: e.message }.to_json)
    render json: { ok: false, error: "revoke_all_internal_error" }, status: :internal_server_error
  end

  private

  # ---- Cookie Options ----
  def base_cookie_options
    {
      path: "/",
      http_only: true,
      same_site: :lax
    }.tap do |opts|
      # 本番は Secure を必ず有効化（HTTPS前提）
      opts[:secure] = Rails.env.production?
    end
  end

  def cookie_options_for_access
    base_cookie_options.merge(max_age: RefreshTokenService::ACCESS_TTL.to_i)
  end

  def cookie_options_for_refresh
    base_cookie_options.merge(max_age: RefreshTokenService::REFRESH_TTL.to_i)
  end

  def cookie_delete_options
    # 削除時も属性を合わせると確実に消える
    base_cookie_options
  end

  # ---- JWT decode（auth_token から user を引く）----
  def current_user_from_auth_cookie
    token = cookies[:auth_token]
    return nil if token.blank?

    payload = decode_auth_jwt(token)
    return nil unless payload && payload["sub"]

    User.find_by(id: payload["sub"])
  rescue
    nil
  end

  def decode_auth_jwt(token)
    secret = Rails.application.credentials.jwt_secret_key || ENV["JWT_SECRET_KEY"]
    decoded, _ = JWT.decode(token, secret, true, { algorithm: "HS256" })
    decoded
  rescue JWT::DecodeError, JWT::ExpiredSignature
    nil
  end
end
