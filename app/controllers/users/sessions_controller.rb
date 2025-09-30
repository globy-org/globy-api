class Users::SessionsController < Devise::SessionsController
  respond_to :json

  # POST /users/sign_in
  def create
    self.resource = warden.authenticate!(auth_options)
    sign_in(resource_name, resource)

    # devise-jwt が発行したトークンは env に入る
    token = request.env['warden-jwt_auth.token']

    render json: {
      user: resource.slice(:id, :email, :name),
      token: token
      # 必要なら exp を返す場合はコメントアウトを外して使う（下に参考コードあり）
      # exp: jwt_exp(token)
    }, status: :ok
  end

  # DELETE /users/sign_out
  def destroy
    sign_out(resource_name)
    render json: { ok: true }, status: :ok
  end

  private

  def respond_with(resource, _opts = {})
    token = request.env['warden-jwt_auth.token']
    render json: {
      user: {
        id: resource.id,
        email: resource.email,
        name: resource.name
      },
      token: token
    }, status: :ok
  end

  def respond_with(resource, _opts = {})
    render json: { user: serialize_user(resource) }, status: :ok
  end

  def respond_to_on_destroy
    head :no_content
  end

  def serialize_user(user)
    { id: user.id, name: user.name, email: user.email }
  end
end
