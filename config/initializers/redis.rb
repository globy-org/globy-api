# config/initializers/redis.rb
# ===================== HYBRID_START:redis =====================
require "connection_pool"

REDIS_POOL = ConnectionPool.new(size: Integer(ENV.fetch("REDIS_POOL_SIZE", 5)), timeout: 2) do
  Redis.new(url: ENV.fetch("REDIS_URL", "redis://localhost:6379/0"))
end

module RedisKeys
  NAMESPACE = ENV.fetch("REDIS_NAMESPACE", "globy")

  # アクティブな refresh_token のキャッシュ
  #   rt:active:<digest> => JSON({ user_id, jti, exp }) (TTL=expires_at)
  def self.rt_active(digest) = "#{NAMESPACE}:rt:active:#{digest}"

  # 失効済みトークン（denylist）
  #   rt:deny:<digest> => "1" (TTL=expires_at まで)
  def self.rt_deny(digest)   = "#{NAMESPACE}:rt:deny:#{digest}"
end
# ===================== HYBRID_END:redis =======================
