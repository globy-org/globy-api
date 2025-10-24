# frozen_string_literal: true
# アクセスJWT → User 復元の責務をコントローラーから分離
class JwtUserResolver
  def initialize(resource_name:)
    @resource_name = resource_name
  end

  # 検証付き→総当たり→（許可時のみ）未検証デコード の順で User を返す
  def resolve_from_access_token(token)
    return nil if token.blank?

    # (A) devise-jwt の UserDecoder（revocation 戦略も通る）
    if defined?(Warden::JWTAuth::UserDecoder)
      begin
        u = Warden::JWTAuth::UserDecoder.new.call(token, @resource_name, nil)
        return u if u.present?
      rescue JWT::DecodeError, JWT::VerificationError, JWT::ExpiredSignature, (Warden::JWTAuth::Errors::RevokedToken if defined?(Warden::JWTAuth::Errors::RevokedToken))
      end
    end

    # (B) devise-jwt TokenDecoder（revocation なし）
    if defined?(Warden::JWTAuth::TokenDecoder)
      begin
        payload = Warden::JWTAuth::TokenDecoder.new.call(token)
        return find_user_from_payload(payload)
      rescue JWT::DecodeError, JWT::VerificationError, JWT::ExpiredSignature
      end
    end

    # (C) HS系複数シークレット ＆ 複数アルゴリズムで総当たり
    hs_secrets = candidate_secrets
    %w[HS256 HS512].each do |alg|
      hs_secrets.each do |secret|
        begin
          payload, = JWT.decode(token, secret, true, { algorithm: alg })
          u = find_user_from_payload(payload)
          return u if u.present?
        rescue JWT::DecodeError, JWT::VerificationError, JWT::ExpiredSignature
        end
      end
    end

    # (D) 開発 or 明示許可時のみ、未検証デコード
    if Rails.env.development? || ENV["ALLOW_UNVERIFIED_ME"] == "1"
      begin
        payload, = JWT.decode(token, nil, false)
        return find_user_from_payload(payload)
      rescue StandardError
      end
    end

    nil
  end

  private

  def find_user_from_payload(payload)
    uid = payload['sub'] || payload['user_id'] || payload['uid'] || payload.dig('user', 'id')
    User.find_by(id: uid)
  end

  def candidate_secrets
    [
      (defined?(RefreshTokenService) && RefreshTokenService.respond_to?(:access_secret)) ? RefreshTokenService.access_secret : nil,
      (defined?(RefreshService)      && RefreshService.respond_to?(:access_secret))      ? RefreshService.access_secret      : nil,
      ENV['REFRESH_TOKEN_ACCESS_SECRET'],
      ENV['JWT_ACCESS_SECRET'],
      ENV['ACCESS_TOKEN_SECRET'],
      (Rails.application.credentials.dig(:jwt, :access_secret) rescue nil),
      (defined?(Warden::JWTAuth) && Warden::JWTAuth.respond_to?(:config)) ? Warden::JWTAuth.config.secret : nil,
      Rails.application.credentials.secret_key_base
    ].compact.uniq
  end
end
