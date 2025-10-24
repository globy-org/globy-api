# app/services/refresh_token_service.rb
# ===================== HYBRID_START:service =====================
require "digest"

class RefreshTokenService
  ACCESS_TTL   = 15.minutes
  REFRESH_TTL  = 30.days

  def initialize(user:)
    @user = user
  end

  # ログイン成功時に呼び出し：DBに保存し、Redisにactiveキャッシュ
  def issue_pair!
    raw_refresh, digest, jti, exp = generate_refresh_payload
    record = RefreshToken.create!(
      user: @user, token_digest: digest, jti: jti, expires_at: exp
    )
    cache_active!(digest, @user.id, jti, exp)
    [issue_access_jwt!(@user), raw_refresh]
  end

  # 検証＋ローテーション：旧refreshが有効なら失効→新規発行（DB & Redis）
  # 戻り値: [new_access_jwt, new_refresh_raw]
  def rotate!(raw_refresh)
    digest = sha256(raw_refresh)

    return nil if denylisted?(digest)

    # まずRedis activeキャッシュを見る（ヒットならDB照会スキップ可）
    hit = fetch_active(digest)
    token = if hit
      RefreshToken.find_by(token_digest: digest, jti: hit["jti"], user_id: hit["user_id"])
    else
      RefreshToken.find_by(token_digest: digest)
    end

    return nil if token.nil? || token.revoked?

    # DBトランザクションで旧をrevoke
    RefreshToken.transaction do
      token.update!(revoked_at: Time.current)
      denylist!(digest, token.expires_at)

      # 新規発行
      raw2, digest2, jti2, exp2 = generate_refresh_payload
      RefreshToken.create!(
        user: token.user, token_digest: digest2, jti: jti2, expires_at: exp2
      )
      cache_active!(digest2, token.user_id, jti2, exp2)

      return [issue_access_jwt!(token.user), raw2]
    end
  end

  # 任意トークンを失効
  def revoke!(raw_refresh)
    digest = sha256(raw_refresh)
    token  = RefreshToken.find_by(token_digest: digest)
    return false unless token
    token.update!(revoked_at: Time.current)
    denylist!(digest, token.expires_at)
    true
  end

  # ユーザーの全refresh失効（全端末ログアウト）
  def revoke_all!
    RefreshToken.active.where(user_id: @user.id).find_each do |t|
      t.update!(revoked_at: Time.current)
      denylist!(t.token_digest, t.expires_at)
    end
    true
  end

  # ---- helpers ----
  private

  def issue_access_jwt!(user)
    secret = Rails.application.credentials.jwt_secret_key || ENV["JWT_SECRET_KEY"]
    now    = Time.now.to_i
    payload = { jti: SecureRandom.uuid, sub: user.id.to_s, scp: "user", iat: now, exp: now + ACCESS_TTL.to_i }
    JWT.encode(payload, secret, "HS256")
  end

  def generate_refresh_payload
    raw = SecureRandom.urlsafe_base64(64)
    [raw, sha256(raw), SecureRandom.uuid, REFRESH_TTL.from_now]
  end

  def sha256(s) = Digest::SHA256.hexdigest(s)

  # Redis: active キャッシュ
  def cache_active!(digest, user_id, jti, expires_at)
    ttl = [expires_at - Time.current, 1.second].max
    REDIS_POOL.with do |r|
      r.setex(RedisKeys.rt_active(digest), ttl.to_i, { user_id:, jti:, exp: expires_at.iso8601 }.to_json)
    end
  end

  def fetch_active(digest)
    REDIS_POOL.with do |r|
      json = r.get(RedisKeys.rt_active(digest))
      json ? JSON.parse(json) : nil
    end
  end

  # Redis: denylist
  def denylisted?(digest)
    REDIS_POOL.with { |r| r.exists(RedisKeys.rt_deny(digest)) }
  end

  def denylist!(digest, expires_at)
    ttl = [expires_at - Time.current, 1.second].max
    REDIS_POOL.with { |r| r.setex(RedisKeys.rt_deny(digest), ttl.to_i, "1") }
    # active キャッシュも消す
    REDIS_POOL.with { |r| r.del(RedisKeys.rt_active(digest)) }
  end
end
# ===================== HYBRID_END:service ======================
