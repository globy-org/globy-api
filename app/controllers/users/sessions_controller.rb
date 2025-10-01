class Users::SessionsController < Devise::SessionsController
  respond_to :json
  before_action :authenticate_user!, only: [:me]

  # POST /users/sign_in
  def create
    self.resource = warden.authenticate!(auth_options)
    sign_in(resource_name, resource)

    token = request.env['warden-jwt_auth.token']

    render json: {
      user: {
        id: resource.id,
        name: resource.name,
        email: resource.email
      },
      token: token
    }, status: :ok
  end

  def me
    if current_user
      render json: {
        user: { id: current_user.id, name: current_user.name, email: current_user.email }
      }, status: :ok
    else
      render json: { error: 'Unauthorized' }, status: :unauthorized
    end
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
