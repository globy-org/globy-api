# frozen_string_literal: true
class Users::SessionsController < Devise::SessionsController
  include ProblemRendering
  include TokenExtraction
  include CookieAuth

  respond_to :json
  before_action :authenticate_user!, only: [:destroy, :sign_out]

  rescue_from JWT::ExpiredSignature do
    render_problem(status: 401, code: "token_expired", title: "Unauthorized", detail: "JWT has expired")
  end
  rescue_from JWT::DecodeError, JWT::VerificationError do
    render_problem(status: 401, code: "invalid_token", title: "Unauthorized", detail: "JWT is invalid")
  end
  if defined?(Warden) && defined?(Warden::JWTAuth::Errors::RevokedToken)
    rescue_from Warden::JWTAuth::Errors::RevokedToken do
      render_problem(status: 401, code: "revoked_token", title: "Unauthorized", detail: "JWT has been revoked")
    end
  end

  # POST /users/sign_in
  def create
    resource = warden.authenticate(scope: resource_name) || manual_auth!
    self.resource = resource

    # セッションを書かずにログイン状態へ
    set_current_user_without_session(resource)

    # トークン発行（devise-jwt or 独自サービス）
    access_jwt  = request.env['warden-jwt_auth.token']
    issued_access, issued_refresh = issue_tokens(resource)
    access_jwt  ||= issued_access
    refresh_jwt = issued_refresh

    set_cookie("auth_token",    access_jwt,  max_age: CookieAuth::AT_MAX_AGE)
    set_cookie("access_token",  access_jwt,  max_age: CookieAuth::AT_MAX_AGE)
    set_cookie("refresh_token", refresh_jwt, max_age: CookieAuth::RT_MAX_AGE)

    render json: { user: serialize_user(resource), token: access_jwt }, status: :ok
  end

  # GET /me
  def me
    user = current_user || (defined?(warden) ? warden.user(scope: resource_name) : nil)

    if user.nil?
      token = extract_any_access_token
      resolver = JwtUserResolver.new(resource_name: resource_name)
      user = resolver.resolve_from_access_token(token) if token.present?
      user ||= RefreshUserResolver.from_cookie(cookies)
      return unauthorized! unless user

      set_current_user_without_session(user)
    end

    render json: { user: serialize_user(user) }, status: :ok
  end

  # DELETE /users/sign_out
  def destroy
    do_sign_out!
    render json: { ok: true }, status: :ok
  end

  # POST /auth/sign_out
  def sign_out
    do_sign_out!
    render json: { ok: true }, status: :ok
  end

  private

  # --- 認証ヘルパ ---
  def manual_auth!
    raw = params[:user] || {}
    email = raw[:email].to_s.strip.downcase
    user  = resource_class.find_for_database_authentication(email: email)
    valid = (user && raw[:password].present?) ? user.valid_password?(raw[:password].to_s) : false
    return user if valid

    render json: { ok: false, code: "invalid_credentials", message: "Invalid Email or password" }, status: :unauthorized and return
  end

  def issue_tokens(user)
    # [access, refresh] を返す（存在しなければ nil）
    if defined?(RefreshService) && RefreshService.respond_to?(:issue_pair)
      return RefreshService.issue_pair(user)
    elsif defined?(RefreshService) && RefreshService.respond_to?(:issue_refresh)
      return [nil, RefreshService.issue_refresh(user)]
    elsif defined?(RefreshTokenService) && RefreshTokenService.respond_to?(:issue_pair!)
      return RefreshTokenService.issue_pair!(user)
    end
    [nil, nil]
  end

  def do_sign_out!
    # dev-jwt の revoke（可能な限り）
    token = bearer_token || request.env['warden-jwt_auth.token']
    try_revoke_access!(token) if token.present?

    # refresh の revoke（存在すれば）
    try_revoke_refresh!

    clear_auth_cookies!
    warden.logout if defined?(warden) && warden
  end

  def try_revoke_access!(jwt)
    return unless defined?(Warden) && defined?(Warden::JWTAuth::TokenDecoder)
    payload = Warden::JWTAuth::TokenDecoder.new.call(jwt) rescue nil
    return unless payload

    user = current_user || User.find_by(id: payload['sub'])
    if user && User.respond_to?(:jwt_revocation_strategy)
      User.jwt_revocation_strategy.revoke_jwt(payload, user)
    elsif user && user.respond_to?(:update)
      user.update!(jti: SecureRandom.uuid)
    end
  end

  def try_revoke_refresh!
    rt = cookies["refresh_token"]
    return unless rt.present?
    if defined?(RefreshService) && RefreshService.respond_to?(:revoke)
      RefreshService.revoke(rt) rescue nil
    elsif defined?(RefreshTokenService) && RefreshTokenService.respond_to?(:revoke!)
      RefreshTokenService.revoke!(rt) rescue nil
    end
  end

  def unauthorized!
    render_problem(status: 401, code: "invalid_token", title: "Unauthorized", detail: "JWT is invalid")
  end

  def serialize_user(user)
    { id: user.id, name: user.name, email: user.email }
  end
end
