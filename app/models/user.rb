class User < ApplicationRecord
  # has_secure_password は除去
  # include Devise modules you need:
  # :confirmable, :lockable, :timeoutable, :trackable は必要に応じて
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :jwt_authenticatable, jwt_revocation_strategy: self

  # JWT のための JTI（トークン識別子）を使う
  include Devise::JWT::RevocationStrategies::JTIMatcher

  before_validation :downcase_email

  validates :name, presence: true, length: { maximum: 50 }

  private

  def downcase_email
    self.email = email.to_s.strip.downcase
  end
end
