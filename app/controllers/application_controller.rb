# app/controllers/application_controller.rb
class ApplicationController < ActionController::API
  # API モードで Cookie を扱う
  include ActionController::Cookies
  # Devise の authenticate_user! / current_user 等
  include Devise::Controllers::Helpers

  # RFC7807 形式のレスポンスヘルパ
  include ProblemRendering  # app/controllers/concerns/problem_rendering.rb

  # Devise Strong Parameters
  before_action :configure_permitted_parameters, if: :devise_controller?

  # --- JWT/認証系の共通ハンドリング（jwt gem 前提） ---
  rescue_from JWT::ExpiredSignature do
    render_problem(
      status: 401,
      code:   "token_expired",
      title:  "Unauthorized",
      detail: "JWT has expired"
    )
  end

  rescue_from JWT::DecodeError, JWT::VerificationError do
    render_problem(
      status: 401,
      code:   "invalid_token",
      title:  "Unauthorized",
      detail: "JWT is invalid"
    )
  end

  # Revocation 戦略などを使っている場合のみ（存在チェックしてから登録）
  if defined?(Warden) && defined?(Warden::JWTAuth) && defined?(Warden::JWTAuth::Errors)
    if defined?(Warden::JWTAuth::Errors::RevokedToken)
      rescue_from Warden::JWTAuth::Errors::RevokedToken do
        render_problem(
          status: 401,
          code:   "revoked_token",
          title:  "Unauthorized",
          detail: "JWT has been revoked"
        )
      end
    end
  end
  # --- 例外ハンドリングここまで ---

  protected

  # Devise Strong Parameters
  def configure_permitted_parameters
    devise_parameter_sanitizer.permit(:sign_up,        keys: [:name])
    devise_parameter_sanitizer.permit(:account_update, keys: [:name])
  end

  # "Authorization: Bearer <token>" を抽出
  def bearer_token
    auth = request.headers["Authorization"].to_s
    auth.start_with?("Bearer ") ? auth.split(" ", 2).last : nil
  end

  # 必要アクションで明示的に呼ぶ「JWT が付いているか」の簡易チェック
  # 例) before_action :authenticate_with_jwt!, only: [:destroy]
  def authenticate_with_jwt!
    token = bearer_token
    if token.blank?
      return render_problem(
        status: 401,
        code:   "missing_token",
        title:  "Unauthorized",
        detail: "Authorization header is missing or invalid"
      )
    end
    # devise-jwt を採用している場合、実際の検証は Warden に委譲でOK
    # 早期検証が必要なら以下を有効化
    # payload = Warden::JWTAuth::TokenDecoder.new.call(token) if defined?(Warden::JWTAuth)
  end

  # ---- Cookie ヘルパ（共通化）----

  # Set-Cookie 共通
  # max_age: ActiveSupport::Duration または秒（Integer）
  def set_cookie(name, value, max_age:)
    return if value.blank?
    cookies[name] = {
      value:     value,
      path:      "/",
      max_age:   max_age,
      httponly:  true,
      same_site: :lax,
      secure:    Rails.env.production? # dev では HTTP でも保存できるように
    }
  end

  # Cookie 削除（path は / 固定で運用）
  def clear_cookie(name)
    cookies.delete(name, path: "/")
  end

  # 認証系 Cookie 一括削除
  def clear_auth_cookies!
    clear_cookie("auth_token")
    clear_cookie("refresh_token")
  end
end
