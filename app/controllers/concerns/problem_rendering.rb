# app/controllers/concerns/problem_rendering.rb
module ProblemRendering
  extend ActiveSupport::Concern

  # RFC 7807: Problem Details っぽい形で返す
  def render_problem(status:, code:, title:, detail: nil, extras: {})
    payload = {
      type:   "about:blank",
      title:  title,   # 例: "Unauthorized"
      status: status,  # 例: 401
      code:   code,    # 例: "token_expired"（機械可読）
      detail: detail,  # 例: "JWT has expired"
    }.merge(extras)

    render json: payload, status: status
  end
end
