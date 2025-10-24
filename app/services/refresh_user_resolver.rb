# frozen_string_literal: true
# refresh_token クッキーから User を復元（実装依存部分を集約）
class RefreshUserResolver
  def self.from_cookie(cookies)
    rt = cookies["refresh_token"]
    return nil unless rt.present?

    # 1) サービス経由（あれば最優先）
    if defined?(RefreshTokenService)
      if RefreshTokenService.respond_to?(:user_for)
        return RefreshTokenService.user_for(rt) rescue nil
      elsif RefreshTokenService.respond_to?(:verify)
        rec = (RefreshTokenService.verify(rt) rescue nil)
        return User.find_by(id: rec.user_id) if rec && rec.respond_to?(:user_id)
      elsif RefreshTokenService.respond_to?(:find_user_by_token)
        return RefreshTokenService.find_user_by_token(rt) rescue nil
      end
    end

    # 2) モデル直叩き（実装に合わせて）
    if defined?(RefreshToken)
      if RefreshToken.respond_to?(:lookup)
        rec = (RefreshToken.lookup(rt) rescue nil)
        return rec.user if rec && rec.respond_to?(:user)
      end

      if RefreshToken.respond_to?(:digest)
        digest = RefreshToken.digest(rt) rescue nil
        if digest && RefreshToken.respond_to?(:find_by)
          rec = RefreshToken.find_by(token_digest: digest)
          return User.find_by(id: rec.user_id) if rec && rec.respond_to?(:user_id)
        end
      end
    end

    nil
  end
end
