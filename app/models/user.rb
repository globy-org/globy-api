class User < ApplicationRecord
  has_secure_password  # ← bcrypt + password_digest で動作

  # email を小文字正規化
  before_validation :downcase_email

  validates :name,  presence: true, length: { maximum: 50 }
  validates :email,
            presence: true,
            length: { maximum: 255 },
            format: { with: /\A[^@\s]+@[^@\s]+\z/ },
            uniqueness: { case_sensitive: false }
  validates :password, length: { minimum: 8 }, if: :password_digest_changed?

  private

  def downcase_email
    self.email = email.to_s.strip.downcase
  end
end
