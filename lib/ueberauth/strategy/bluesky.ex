defmodule Ueberauth.Strategy.Bluesky do
  use Ueberauth.Strategy, ignores_csrf_attack: true
  alias Ueberauth.Auth.Extra

  alias OAuth2.Strategy.AuthCode
  require Logger

  # these may be variable per atproto, but they're hardcoded for the sake of this strategy
  @site "https://bsky.social"
  @authorize_url "#{@site}/oauth/authorize"
  @token_url "#{@site}/oauth/token"
  @par_url "#{@site}/oauth/par"

  # this could be improved as it's a centralized point of trust that isn't bluesky itself
  @plc_site "https://plc.directory/"

  def handle_request!(conn) do
    client = oauth2_client()
    {code_verifier, code_challenge} = pkce_challenge()
    conn = Plug.Conn.put_session(conn, :pkce_verifier, code_verifier)
    username = conn.params["username"]
    conn = Plug.Conn.put_session(conn, :user_handle, username)

    state = UUID.uuid4()
    conn = Plug.Conn.put_session(conn, :ueberauth_state_param, state)

    auth_params = %{
      "client_id" => client.client_id,
      "response_type" => "code",
      "redirect_uri" => client.redirect_uri,
      "state" => state,
      "scope" => "atproto", 
      "code_challenge" => code_challenge,
      "code_challenge_method" => "S256",
      "username" => username 
    }

    dpop_key = generate_dpop_key()

    conn = Plug.Conn.put_session(conn, :dpop_key, dpop_key)

    with {:ok, request_uri} <- push_authorization_request(auth_params, dpop_key) do
      redirect_url = "#{@authorize_url}?client_id=#{client.client_id}&request_uri=#{URI.encode_www_form(request_uri)}"
      conn
      |> Plug.Conn.put_resp_header("location", redirect_url)
      |> Plug.Conn.send_resp(302, "")
      |> Plug.Conn.halt()

    else
      {:error, reason} ->
        Logger.error("PAR request failed: #{inspect(reason)}")
        conn
    end
  end

    
  def handle_callback!(%Plug.Conn{params: %{"code" => code, "state" => incoming_state}} = conn) do
    stored_state = Plug.Conn.get_session(conn, :ueberauth_state_param)

    if incoming_state != stored_state do
      conn
      |> Plug.Conn.put_status(:forbidden)
      |> Plug.Conn.send_resp(403, "Invalid CSRF state")
      |> Plug.Conn.halt()
    else
      client = oauth2_client()
      code_verifier = Plug.Conn.get_session(conn, :pkce_verifier)
      dpop_key = Plug.Conn.get_session(conn, :dpop_key)
      user_handle = Plug.Conn.get_session(conn, :user_handle)

      token_params = [
        client_id: System.fetch_env!("BLUESKY_CLIENT_ID"),
        code: code,
        grant_type: "authorization_code",
        redirect_uri: client.redirect_uri,
        code_verifier: code_verifier,
        client_assertion: generate_client_assertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
      ]

      dpop_proof = generate_dpop_proof("POST", @token_url, dpop_key)
      headers = [{"DPoP", dpop_proof}]

      client = OAuth2.Client.put_headers(client, headers)

      case OAuth2.Client.get_token(client, token_params) do
        {:ok, token} ->
          conn
          |> put_private(:bluesky_token, token)
          |> clear_oauth_session()
          verify_handle(conn, user_handle, token)

        {:error, %OAuth2.Response{headers: resp_headers} = error_resp} ->
          nonce = Enum.find_value(resp_headers, fn
            {"dpop-nonce", nonce} -> nonce
            _ -> nil
          end)

          if nonce do
            # Retry once with nonce
            headers_with_nonce = [
              {"DPoP", generate_dpop_proof("POST", @token_url, dpop_key, nonce)}
            ]

            client = OAuth2.Client.put_headers(client, headers_with_nonce)

            case OAuth2.Client.get_token(client, token_params) do
              {:ok, token} ->
                {:ok, decoded_token} = Jason.decode(token.token.access_token)
                did = decoded_token["sub"]
                conn = verify_handle(conn, user_handle, did)

                auth = %Ueberauth.Auth{
                  provider: :bluesky,
                  uid: did,
                  info: %Ueberauth.Auth.Info{
                    nickname: user_handle
                  },
                  extra: %{ }
                }
                conn
                |> put_private(:ueberauth_user_handle, user_handle)
                |> put_private(:ueberauth_uid, did)
                |> put_private(:ueberauth_auth, auth)
                |> put_private(:bluesky_token, decoded_token)
                |> clear_oauth_session()


              {:error, reason} ->
                Logger.error("Token exchange failed after dpop-nonce retry: #{inspect(reason)}")
                conn
            end
          else
            Logger.error("Token exchange failed: #{inspect(error_resp)}")
            conn
          end

        {:error, reason} ->
          Logger.error("Token exchange failed: #{inspect(reason)}")
          conn
      end
    end
  end


  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.bluesky_token,
        did: conn.private.ueberauth_uid,
        handle: conn.private.ueberauth_user_handle
      }
    }
  end

  defp clear_oauth_session(conn) do
    conn
    |> Plug.Conn.delete_session(:ueberauth_state_param)
    |> Plug.Conn.delete_session(:pkce_verifier)
    |> Plug.Conn.delete_session(:dpop_key)
  end

  defp verify_handle(conn, handle, did) do
    url = "https://plc.directory/#{did}"

    case Req.get(
      url: url,
      redirect: false
    ) do
      {:ok, %Req.Response{status: 200, body: body}} ->

        case Jason.decode(body) do
          {:ok, result_map} ->
            also_known_as = Map.get(result_map, "alsoKnownAs", [])


            if "at://#{handle}" in also_known_as do
              conn
              |> put_private(:bluesky_user_did, did)
            else
              set_errors!(conn, [
                error("handle_verification_failed", "Handle mismatch: expected at://#{handle} in #{inspect(also_known_as)}")
              ])
            end

          {:error, reason} ->
            set_errors!(conn, [error("json_decode_failed", inspect(reason))])
        end


      {:ok, %Req.Response{status: status, body: body}} ->
        set_errors!(conn, [error("plc_fetch_failed", "HTTP #{status}: #{inspect(body)}")])

      {:error, reason} ->
        set_errors!(conn, [error("plc_fetch_failed", inspect(reason))])
    end
  end


  defp oauth2_client do
    OAuth2.Client.new(
      strategy: AuthCode,
      client_id: System.fetch_env!("BLUESKY_CLIENT_ID"),
      site: @site,
      redirect_uri: System.fetch_env!("BLUESKY_REDIRECT_URI"),
      authorize_url: @authorize_url,
      token_url: @token_url
    )
  end

  defp generate_client_assertion do
    pem = System.fetch_env!("CLIENT_PRIVATE_KEY_B64") |> Base.decode64!()
    key = JOSE.JWK.from_pem(pem)
    now = System.system_time(:second)
    exp = now + 300
    jti = UUID.uuid4()
    client_id = System.fetch_env!("BLUESKY_CLIENT_ID")

    claims = %{
      "iss" => client_id,
      "sub" => client_id,
      "aud" => @token_url,
      "exp" => exp,
      "iat" => now,
      "jti" => jti
    }

    {_, jwt} = JOSE.JWT.sign(key, %{"alg" => "ES256"}, claims) |> JOSE.JWS.compact()
    jwt
  end


  defp get_dpop_nonce(headers) do
    headers
    |> Enum.find_value(fn
      {key, value} ->
        if String.downcase(key) == "dpop-nonce" do
          value
        else
          nil
        end

      _ -> nil
    end)
  end

  defp maybe_put_username(map, nil), do: map
  defp maybe_put_username(map, ""), do: map
  defp maybe_put_username(map, username), do: Map.put(map, "username", username)

  defp generate_dpop_key do
    JOSE.JWK.generate_key({:ec, :secp256r1})
  end

  defp generate_dpop_proof(method, url, key, nonce \\ nil) do
    now = System.system_time(:second)
    jti = UUID.uuid4()
    uri = URI.parse(url)
    htu = "#{uri.scheme}://#{uri.host}#{uri.path}"

    claims = %{
      "htu" => htu,
      "htm" => method,
      "iat" => now,
      "jti" => jti
    }
    |> maybe_put_nonce(nonce)

    header = %{
      "typ" => "dpop+jwt",
      "alg" => "ES256",
      # "jwk" => JOSE.JWK.to_map(key) |> elem(1)
      "jwk" => JOSE.JWK.to_public(key) |> JOSE.JWK.to_map() |> elem(1)
    }

    {_, jwt} = JOSE.JWT.sign(key, header, claims) |> JOSE.JWS.compact()
    jwt
  end

  defp maybe_put_nonce(claims, nil), do: claims
  defp maybe_put_nonce(claims, nonce), do: Map.put(claims, "nonce", nonce)

  defp push_authorization_request(params, dpop_key) do
    do_push_authorization_request(params, dpop_key, nil)
  end

  defp do_push_authorization_request(params, dpop_key, nonce) do
    headers = [
      {"Content-Type", "application/x-www-form-urlencoded"},
      {"Accept", "application/json"},
      {"DPoP", generate_dpop_proof("POST", @par_url, dpop_key, nonce)}
    ]

    client_assertion = generate_client_assertion()
    params = Map.merge(params, %{
      "client_assertion" => client_assertion,
      "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    })

    body = URI.encode_query(params)

    case :hackney.post(@par_url, headers, body, []) do
      {:ok, status, _headers, client_ref} when status in [200, 201] ->
        {:ok, response_body} = :hackney.body(client_ref)
        case Jason.decode(response_body) do
          {:ok, %{"request_uri" => request_uri}} -> {:ok, request_uri}
          error -> {:error, error}
        end

      {:ok, 400, resp_headers, client_ref} ->
        {:ok, response_body} = :hackney.body(client_ref)

        case get_dpop_nonce(resp_headers) do
          nil ->
            Logger.error("PAR request failed (400): #{response_body}")
            {:error, :par_request_failed}
          nonce ->
            Logger.info("Retrying PAR request with nonce: #{nonce}")
            do_push_authorization_request(params, dpop_key, nonce)
        end

      {:ok, status, _headers, client_ref} ->
        {:ok, response_body} = :hackney.body(client_ref)
        Logger.error("PAR request failed with status #{status}: #{response_body}")
        {:error, :par_request_failed}

      {:error, reason} ->
        Logger.error("PAR request error: #{inspect(reason)}")
        {:error, reason}
    end
  end

  def generate_code_verifier(length \\ 64) do
    :crypto.strong_rand_bytes(length)
    |> Base.url_encode64(padding: false)
  end

  def generate_code_challenge(code_verifier) do
    :crypto.hash(:sha256, code_verifier)
    |> Base.url_encode64(padding: false)
  end

  def pkce_challenge() do
    verifier = generate_code_verifier()
    challenge = generate_code_challenge(verifier)
    {verifier, challenge}
  end
end
