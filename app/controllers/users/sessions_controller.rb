# app/controllers/users/sessions_controller.rb
class Users::SessionsController < Devise::SessionsController
  include ProblemRendering

  respond_to :json
  before_action :authenticate_user!, only: [:me, :destroy]

  # --- JWTエラーの共通ハンドリング（jwt gem 由来は常に存在する） ---
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

  # 任意：Revocation 戦略を使っていて、かつ定義が存在する場合のみハンドリング
  if defined?(Warden) && defined?(Warden::JWTAuth::Errors::RevokedToken)
    rescue_from Warden::JWTAuth::Errors::RevokedToken do
      render_problem(
        status: 401,
        code:   "revoked_token",
        title:  "Unauthorized",
        detail: "JWT has been revoked"
      )
    end
  end

  # POST /users/sign_in
  def create
    self.resource = warden.authenticate!(auth_options)
    sign_in(resource_name, resource)
    token = request.env['warden-jwt_auth.token']

    render json: {
      user: serialize_user(resource),
      token: token
    }, status: :ok
  end

  # GET /me
  def me
    # authenticate_user! 済みのため current_user は存在する想定
    render json: { user: serialize_user(current_user) }, status: :ok
  end

  # DELETE /users/sign_out
  # - devise-jwt（JTIMatcher 想定）でトークン失効
  def destroy
    token = bearer_token || request.env['warden-jwt_auth.token']
    revoke_token!(token) if token.present?

    sign_out(resource_name)
    render json: { ok: true }, status: :ok
  end

  private

  # ---- 失効処理（devise-jwt / JTIMatcher 想定）----
  # User が `devise :jwt_authenticatable, jwt_revocation_strategy: self` の場合に対応
  def revoke_token!(jwt)
    return unless jwt.present?

    payload = nil
    if defined?(Warden) && defined?(Warden::JWTAuth) && defined?(Warden::JWTAuth::TokenDecoder)
      # TokenDecoder が存在する場合のみ実行
      begin
        payload = Warden::JWTAuth::TokenDecoder.new.call(jwt)
      rescue JWT::DecodeError, JWT::VerificationError, JWT::ExpiredSignature
        # 失効手続きはスキップ（無効トークン）
        return
      end
    else
      # Warden がないバージョン構成なら decode はせず終了
      return
    end

    user = current_user || User.find_by(id: payload['sub'])

    # 共通 Strategy（例: Devise::JWT::RevocationStrategies::JTIMatcher）
    if user && User.respond_to?(:jwt_revocation_strategy)
      User.jwt_revocation_strategy.revoke_jwt(payload, user)
    elsif user && user.respond_to?(:update)
      # フォールバック: JTIMatcher相当（jtiをローテーション）
      user.update!(jti: SecureRandom.uuid)
    end
  end

  # "Authorization: Bearer <JWT>" からトークンを取り出す
  def bearer_token
    auth = request.headers["Authorization"].to_s
    auth.start_with?("Bearer ") ? auth.split(" ", 2).last : nil
  end

  # ---- Devise の JSON レスポンス統一 ----
  def respond_with(resource, _opts = {})
    token = request.env['warden-jwt_auth.token']
    render json: { user: serialize_user(resource), token: token }, status: :ok
  end

  def respond_to_on_destroy
    render json: { ok: true }, status: :ok
  end

  def serialize_user(user)
    { id: user.id, name: user.name, email: user.email }
  end
end
