defmodule Mix.Tasks.Gen.AuthExtend do
  @shortdoc "Extends phx.gen.auth: roles/groups in scope, API tokens, Assent SSO"

  @moduledoc """
  Igniter task that extends a stock `mix phx.gen.auth` setup with:

    * `role` on users and `group_ids` in the Accounts.Scope
    * API tokens stored in the stock `users_tokens` table (context
      "api-token"), mirroring the official "API Authentication" guide
    * SSO via Assent (OAuth2/OIDC) with a `user_identities` linking table
    * A provider dropdown on the login LiveView that starts the SSO flow
      (hidden when no providers are configured)

  Elixir-file injections are AST-aware (zipper based), so they survive
  formatting differences, and Igniter shows a diff and asks before
  writing. The one HEEx injection (the login form) is done as a string
  update inside the `~H` sigil node, because HEEx has no AST support in
  Igniter.

  ## Installation (per project)

  Add to mix.exs (git dependency):

      {:gen_auth_extend,
       git: "https://github.com/YOU/gen_auth_extend.git", only: :dev}

  Or as a local path dependency while iterating:

      {:gen_auth_extend, path: "../gen_auth_extend", only: :dev}

  Then:

      mix deps.get
      mix gen.auth_extend

  Use `--dry-run` to preview the diff without writing, and `--yes` to
  skip confirmation.

  ## Options

      --context  Accounts context name (default: Accounts)
      --schema   User schema name (default: User)

  ## Manual steps after running

      1. Configure providers: config :my_app, :sso_providers, [...]
      2. mix ecto.migrate
  """

  use Igniter.Mix.Task

  alias Sourceror.Zipper

  @impl Igniter.Mix.Task
  def info(_argv, _composing_task) do
    %Igniter.Mix.Task.Info{
      schema: [context: :string, schema: :string],
      example: "mix gen.auth_extend --context Accounts --schema User"
    }
  end

  @impl Igniter.Mix.Task
  def igniter(igniter) do
    opts = igniter.args.options

    # inspect/1 renders "FonWeb" - to_string/1 on a module atom would
    # render "Elixir.FonWeb", which leaked "Elixir." prefixes everywhere.
    web = inspect(Igniter.Libs.Phoenix.web_module(igniter))
    base = String.replace_suffix(web, "Web", "")
    app = to_string(Mix.Project.config()[:app])
    context = opts[:context] || "Accounts"
    schema = opts[:schema] || "User"

    assigns = [app: app, base: base, web: web, context: context]

    {context_exists?, igniter} =
      Igniter.Project.Module.module_exists(igniter, mod([base, context]))

    if not context_exists? do
      Igniter.add_issue(
        igniter,
        "expected #{base}.#{context} to exist - run " <>
          "`mix phx.gen.auth #{context} #{schema} #{Macro.underscore(schema)}s` first"
      )
    else
      igniter
      |> Igniter.Project.Deps.add_dep({:assent, "~> 0.3"})
      |> create_migration(assigns)
      |> create_support_modules(assigns)
      |> replace_scope(assigns)
      |> extend_user(assigns, schema)
      |> extend_user_token(assigns)
      |> extend_accounts(assigns)
      |> extend_user_auth(assigns)
      |> extend_login(assigns)
      |> extend_router(assigns)
      |> add_example_api_scope(assigns)
      |> Igniter.add_notice(next_steps(assigns))
    end
  end

  # Orchestration

  defp create_migration(igniter, assigns) do
    if Path.wildcard("priv/repo/migrations/*_extend_auth_with_roles_groups_and_sso.exs") != [] do
      Igniter.add_warning(igniter, "auth extension migration already exists - skipping")
    else
      Igniter.create_new_file(
        igniter,
        "priv/repo/migrations/#{timestamp()}_extend_auth_with_roles_groups_and_sso.exs",
        render(migration(), assigns)
      )
    end
  end

  defp create_support_modules(igniter, assigns) do
    base = assigns[:base]
    context = assigns[:context]
    web = assigns[:web]

    igniter
    |> create_module(mod([base, context, "Group"]), group(), assigns)
    |> create_module(mod([base, context, "UserIdentity"]), user_identity(), assigns)
    |> create_module(mod([base, context, "SSO"]), sso_context(), assigns)
    |> create_module(mod([web, "SSOController"]), sso_controller(), assigns)
  end

  defp create_module(igniter, module, template, assigns) do
    {exists?, igniter} = Igniter.Project.Module.module_exists(igniter, module)

    if exists? do
      Igniter.add_warning(igniter, "#{inspect(module)} already exists - leaving it as is")
    else
      Igniter.Project.Module.create_module(igniter, module, module_body(render(template, assigns)))
    end
  end

  # Igniter's create_module wraps the given body in `defmodule module do
  # ... end` itself, so hand it only the inside of our full-file templates:
  # drop the `defmodule ... do` header line and the final `end`.
  defp module_body(source) do
    {_header, rest} =
      Enum.split_while(String.split(source, "\n"), fn line ->
        not String.starts_with?(line, "defmodule")
      end)

    rest
    |> Enum.drop(1) # drop the `defmodule ... do` line itself
    |> Enum.reverse()
    |> Enum.drop_while(&(&1 == ""))
    |> Enum.drop(1)
    |> Enum.reverse()
    |> Enum.join("\n")
  end

  defp replace_scope(igniter, assigns) do
    module = mod([assigns[:base], assigns[:context], "Scope"])

    update_module(igniter, module, "scope", fn zipper ->
      replace_module(zipper, render(scope(), assigns))
    end)
  end

  defp extend_user(igniter, assigns, schema) do
    module = mod([assigns[:base], assigns[:context], schema])

    code = """
    field :role, :string, default: "user"
    many_to_many :groups, #{assigns[:base]}.#{assigns[:context]}.Group, join_through: "user_groups"
    """

    update_module(igniter, module, "user schema", fn zipper ->
      if has_field?(zipper, :role) do
        {:ok, zipper}
      else
        case Zipper.find(zipper, fn node -> field?(node, :email) end) do
          nil ->
            {:warning,
             "could not find `field :email` in the user schema. " <>
               "Add role and groups manually:\n\n#{code}"}

          z ->
            {:ok, add(z, code, :after)}
        end
      end
    end)
  end

  defp extend_user_token(igniter, assigns) do
    module = mod([assigns[:base], assigns[:context], "UserToken"])

    update_module(igniter, module, "user token", fn zipper ->
      apply_while_ok(zipper, [
        {"add @api_token_validity_in_days",
         fn z ->
           if has_attr?(z, :api_token_validity_in_days) do
             {:ok, z}
           else
             inject_attr_after(z, :session_validity_in_days, "@api_token_validity_in_days 365")
           end
         end},
        {"add verify_api_token_query/1",
         fn z ->
           inject_def(
             z,
             :verify_session_token_query,
             1,
             verify_api_token_code(),
             :verify_api_token_query,
             1
           )
         end}
      ])
    end)
  end

  defp extend_accounts(igniter, assigns) do
    update_module(igniter, mod([assigns[:base], assigns[:context]]), "accounts context", fn zipper ->
      inject_def(
        zipper,
        :get_user_by_session_token,
        1,
        accounts_api_code(),
        :create_user_api_token,
        1
      )
    end)
  end

  defp extend_user_auth(igniter, assigns) do
    update_module(igniter, mod([assigns[:web], "UserAuth"]), "user auth plugs", fn zipper ->
      inject_def(
        zipper,
        :fetch_current_scope_for_user,
        2,
        api_plug_code(),
        :fetch_current_scope_for_api_user,
        2
      )
    end)
  end

  defp extend_login(igniter, assigns) do
    module = mod([assigns[:web], "UserLive", "Login"])

    update_module(igniter, module, "login LiveView", fn zipper ->
      apply_while_ok(zipper, [
        {"add the SSO provider form to the template", &inject_sso_form/1},
        {"add the `sso` submit handler", &inject_sso_handler/1},
        {"set sso_providers/sso_form assigns in mount/3", &inject_sso_assigns(&1, assigns)}
      ])
    end)
  end

  defp extend_router(igniter, assigns) do
    web = assigns[:web]

    routes_code = """
    get "/auth/:provider", #{web}.SSOController, :request
    get "/auth/:provider/callback", #{web}.SSOController, :callback
    """

    update_module(igniter, mod([web, "Router"]), "router", fn zipper ->
      apply_while_ok(zipper, [
        {"add the SSO routes", &inject_sso_routes(&1, routes_code)},
        {"add the API token plug to the :api pipeline", &inject_api_plug/1}
      ])
    end)
  end

  defp add_example_api_scope(igniter, assigns) do
    router = mod([assigns[:web], "Router"])

    {igniter, api_scope?} =
      case Igniter.Project.Module.find_module(igniter, router) do
        {:ok, {igniter, _source, zipper}} ->
          {igniter,
           Zipper.find(zipper, fn node ->
             match?({:scope, _, ["/api" | _]}, node)
           end) != nil}

        {:error, igniter} ->
          {igniter, false}
      end

    if api_scope? do
      igniter
    else
      Igniter.Libs.Phoenix.add_scope(
        igniter,
        "/api",
        """
        # Example: get "/me", MeController, :show
        # Routes here require "authorization: Bearer <token>"
        """,
        arg2: Module.concat([assigns[:web]]),
        placement: :after
      )
    end
  end

  # Zipper injection helpers

  defp update_module(igniter, module, label, updater) do
    # normalize: updaters always start from the file root, so searches
    # cover the whole module regardless of where the module was found
    updater = fn zipper -> updater.(Zipper.topmost(zipper)) end

    case Igniter.Project.Module.find_and_update_module(igniter, module, updater) do
      {:ok, igniter} ->
        igniter

      {:error, igniter} ->
        Igniter.add_warning(
          igniter,
          "could not find #{inspect(module)} (#{label}) - skipping, " <>
            "check the generated code manually"
        )
    end
  end

  # Runs the labeled steps in order, stopping at the first failure.
  # Igniter applies module updates all-or-nothing, so when one step
  # fails, the later steps cannot run in the same pass - the warning
  # therefore names the skipped steps. Since every step checks for its
  # own previous work, rerunning the task after fixing picks up exactly
  # the remaining ones.
  defp apply_while_ok(zipper, steps) do
    steps
    |> Enum.reduce_while(zipper, fn {label, fun}, zipper ->
      case fun.(zipper) do
        {:ok, zipper} -> {:cont, zipper}
        {:warning, message} -> {:halt, {:warning, message, label}}
      end
    end)
    |> case do
      {:warning, message, failed} ->
        skipped =
          steps
          |> Enum.map(&elem(&1, 0))
          |> Enum.drop_while(&(&1 != failed))
          |> Enum.drop(1)

        skipped_note =
          if skipped == [] do
            ""
          else
            "\n\nBecause this step failed, these were NOT attempted: " <>
              Enum.join(skipped, ", ") <>
              ". The task is idempotent: fix the problem above (or apply " <>
              "it manually), then rerun `mix gen.auth_extend` - it skips " <>
              "already-applied steps and runs the remaining ones."
          end

        {:warning, message <> skipped_note}

      zipper ->
        {:ok, zipper}
    end
  end

  # Inserts `code` before the def `target/arity`, moving above its
  # @doc/@spec/@impl attributes. Skips when `existing/existing_arity`
  # is already defined (idempotency).
  defp inject_def(zipper, target, arity, code, existing, existing_arity) do
    if has_def?(zipper, existing, existing_arity) do
      {:ok, zipper}
    else
      inject_before_def(zipper, target, arity, code)
    end
  end

  defp inject_before_def(zipper, name, arity, code) do
    case find_def(zipper, name, arity) do
      nil ->
        {:warning,
         "could not find `def #{name}/#{arity}` to anchor an injection. " <>
           "Add this manually:\n\n#{code}"}

      zipper ->
        {:ok, zipper |> move_above_attrs() |> add(code, :before)}
    end
  end

  # Walks left past @doc/@spec/@impl attributes so an injection lands
  # above them, not between the attribute and its def.
  defp move_above_attrs(zipper) do
    case Zipper.left(zipper) do
      nil ->
        zipper

      left ->
        case Zipper.node(left) do
          {:@, _, _} -> move_above_attrs(left)
          _ -> zipper
        end
    end
  end

  defp inject_attr_after(zipper, target, code) do
    case Zipper.find(zipper, fn node -> attr?(node, target) end) do
      nil ->
        {:warning,
         "could not find `@#{target}` to anchor an injection. " <>
           "Add this manually:\n\n#{code}"}

      z ->
        {:ok, add(z, code, :after)}
    end
  end

  # HEEx: Igniter has no AST support for ~H contents, so we patch the
  # sigil's string in place. Preferred anchor: the divider between the
  # magic-link and password forms (prefixed with the SSO form). Fallback
  # (divider markup differs between Phoenix versions): the SSO form is
  # appended after the last `</.form>` in the template.
  defp inject_sso_form(zipper) do
    divider = ~s(<div class="divider">or</div>)
    form = String.trim(sso_form_block())

    sigil? = fn node ->
      case node do
        {:sigil_H, _, [{:__block__, _, [content]}, _]} -> String.contains?(content, "</.form>")
        _ -> false
      end
    end

    missing = fn reason ->
      {:warning,
       "#{reason} in the login LiveView. Add the SSO form block manually " <>
         "(e.g. after the last form):\n\n#{form}"}
    end

    case Zipper.find(zipper, sigil?) do
      nil ->
        missing.("could not find the login form's `~H` template")

      sigil_zipper ->
        case Zipper.down(sigil_zipper) do
          nil ->
            missing.("could not descend into the `~H` template")

          str_zipper ->
            case Zipper.node(str_zipper) do
              {:__block__, meta, [content]} when is_binary(content) ->
                cond do
                  String.contains?(content, "login_form_sso") ->
                    {:ok, zipper}

                  String.contains?(content, divider) ->
                    {:ok,
                     str_zipper
                     |> Zipper.replace(
                       {:__block__, meta,
                        [String.replace(content, divider, form <> "\n\n" <> divider, global: false)]}
                     )
                     |> Zipper.topmost()}

                  true ->
                    # No recognized divider - append after the last form.
                    parts = String.split(content, "</.form>")
                    {head, [tail]} = Enum.split(parts, -1)

                    {:ok,
                     str_zipper
                     |> Zipper.replace(
                       {:__block__, meta,
                        [Enum.join(head, "</.form>") <> "</.form>\n\n" <> form <> "\n" <> tail]}
                     )
                     |> Zipper.topmost()}
                end

              _ ->
                missing.("could not read the `~H` template contents")
            end
        end
    end
  end

  defp inject_sso_handler(zipper) do
    already? =
      find_def(zipper, :handle_event, 3, fn args ->
        args != nil and arg_value(List.first(args)) == "sso"
      end) != nil

    if already? do
      {:ok, zipper}
    else
      inject_before_def(zipper, :handle_event, 3, sso_handler_code())
    end
  end

  defp inject_sso_assigns(zipper, assigns) do
    code = """
    socket = assign(socket, sso_providers: #{assigns[:base]}.#{assigns[:context]}.SSO.configured_providers())
    socket = assign(socket, sso_form: to_form(%{"provider" => nil}, as: "user"))
    """

    if has_assign_key?(zipper, :sso_providers) do
      {:ok, zipper}
    else
      case Zipper.find(zipper, fn node -> ok_assign?(node, :trigger_submit) end) do
        nil ->
          {:warning,
           "could not find the `{:ok, assign(socket, form: form, trigger_submit: false)}` " <>
             "line in mount/3 of the login LiveView. Add these manually:\n\n#{code}"}

        z ->
          {:ok, add(z, code, :before)}
      end
    end
  end

  defp inject_sso_routes(zipper, code) do
    if has_route?(zipper, "/auth/:provider") do
      {:ok, zipper}
    else
      case Zipper.find(zipper, fn node -> match?({:unauthenticated_routes, _, _}, node) end) do
        nil ->
          {:warning,
           "could not find `unauthenticated_routes` in the router. " <>
             "Add the SSO routes manually:\n\n#{code}"}

        z ->
          {:ok, add(z, code, :before)}
      end
    end
  end

  defp inject_api_plug(zipper) do
    if has_api_plug?(zipper) do
      {:ok, zipper}
    else
      case Zipper.find(zipper, fn node -> accepts_json_plug?(node) end) do
        nil ->
          {:warning,
           "could not find `plug :accepts, [\"json\"]` in the :api pipeline. " <>
             "Add `plug :fetch_current_scope_for_api_user` manually."}

        z ->
          {:ok, add(z, "plug :fetch_current_scope_for_api_user", :after)}
      end
    end
  end

  # Whole-module replacement (scope.ex is rewritten wholesale, matching
  # the stock phx.gen.auth scope plus role/group_ids).
  defp replace_module(zipper, contents) do
    with {:ok, ast} <- Code.string_to_quoted(contents),
         module_zipper when not is_nil(module_zipper) <-
           Zipper.find(Zipper.topmost(zipper), fn node -> match?({:defmodule, _, [_, _]}, node) end) do
      {:ok, Zipper.topmost(Zipper.replace(module_zipper, ast))}
    else
      _ ->
        {:warning,
         "could not rewrite the scope module. Replace its contents manually:\n\n#{contents}"}
    end
  end

  defp add(zipper, code, placement) do
    zipper
    |> Igniter.Code.Common.add_code(code, placement: placement)
    |> Zipper.topmost()
  end

  # AST predicates

  defp mod(parts), do: Module.concat(parts)

  defp has_def?(zipper, name, arity) do
    find_def(zipper, name, arity) != nil
  end

  defp find_def(zipper, name, arity, arg_pred \\ fn _ -> true end) do
    Zipper.find(zipper, fn node ->
      case node do
        {:def, _, [{n, _, args}, _]} when is_atom(n) ->
          n == name and def_arity(args) == arity and arg_pred.(args || [])

        _ ->
          false
      end
    end)
  end

  defp def_arity(nil), do: 0
  defp def_arity(args) when is_list(args), do: length(args)

  defp has_attr?(zipper, name) do
    Zipper.find(zipper, fn node -> attr?(node, name) end) != nil
  end

  defp attr?({:@, _, [{name, _, _}]}, target) when is_atom(name), do: name == target
  defp attr?(_, _), do: false

  defp has_field?(zipper, name) do
    Zipper.find(zipper, fn node -> field?(node, name) end) != nil
  end

  defp field?({:field, _, [name_arg | _]}, name), do: arg_value(name_arg) == name
  defp field?(_, _), do: false

  defp has_assign_key?(zipper, key) do
    Zipper.find(zipper, fn node -> assign_key?(node, key) end) != nil
  end

  defp assign_key?({:assign, _, [_, kw_arg]}, key), do: kw_has?(arg_value(kw_arg), key)

  # Matches the `{:ok, assign(socket, ..., trigger_submit: false)}` line
  # in mount so the SSO assigns are added as statements before it.
  defp ok_assign?({:ok, {:assign, _, [_, kw_arg]}}, key), do: kw_has?(arg_value(kw_arg), key)

  defp ok_assign?({:__block__, _, [{:ok, {:assign, _, [_, kw_arg]}}]}, key),
    do: kw_has?(arg_value(kw_arg), key)

  defp ok_assign?(_, _), do: false

  defp kw_has?(kw, key) when is_list(kw), do: Keyword.has_key?(kw, key)
  defp kw_has?(_, _), do: false

  defp has_route?(zipper, path) do
    Zipper.find(zipper, fn node ->
      case node do
        {verb, _, [^path | _]} when verb in [:get, :post, :put, :patch, :delete] -> true
        _ -> false
      end
    end) != nil
  end

  defp has_api_plug?(zipper) do
    Zipper.find(zipper, fn node ->
      case node do
        {:plug, _, [arg]} ->
          case arg_value(arg) do
            :fetch_current_scope_for_api_user -> true
            {name, _, _} -> name == :fetch_current_scope_for_api_user
            _ -> false
          end

        _ ->
          false
      end
    end) != nil
  end

  defp accepts_json_plug?({:plug, _, [{:accepts, _, [types]}]}) do
    types
    |> List.wrap()
    |> Enum.any?(&(&1 == "json" or arg_value(&1) == "json"))
  end

  defp accepts_json_plug?(_), do: false

  # Sourceror wraps literal call arguments in blocks; unwrap one level.
  defp arg_value({:__block__, _, [value]}), do: value
  defp arg_value(value), do: value

  # Output

  defp next_steps(assigns) do
    app = assigns[:app]
    base = assigns[:base]

    """
    Next steps:

      1. Configure your providers (config/dev.exs, config/runtime.exs, ...):

           config :#{app}, :sso_providers,
             google: [
               client_id: System.get_env("GOOGLE_CLIENT_ID"),
               client_secret: System.get_env("GOOGLE_CLIENT_SECRET"),
               strategy: Assent.Strategy.Google
             ]

         Assent ships strategies for Google, Github, OIDC, generic OAuth2,
         and more. Each configured provider appears in the "Sign in with"
         dropdown on the login page (the whole section is hidden when none
         are). Assent's default HTTP adapter is :httpc - add {:finch, "~> 0.16"}
         plus http_adapter: {Assent.HTTPAdapter.Finch, supervisor: #{base}.Finch}
         for production.

      2. Run migrations:

           mix ecto.migrate

      3. API tokens (mirrors the official "API Authentication" guide):

           token = #{base}.Accounts.create_user_api_token(user)
           {:ok, user} = #{base}.Accounts.fetch_user_by_api_token(token)

         Send the token as "authorization: Bearer <token>". The generator added
         fetch_current_scope_for_api_user/2 to UserAuth and to the :api
         pipeline, so routes with pipe_through [:api] require a valid token.
         Tokens live in the stock users_tokens table (hashed, context
         "api-token"), are valid for 365 days, and are voided if the user
         changes their email - just like sessions, they are revoked by stock
         flows such as password change/confirmation.

      4. Roles and groups: use `scope.role` / `scope.group_ids` in policies,
         e.g. `if scope.role == "admin"`. Manage groups with any CRUD
         mechanism you like (mix phx.gen.html, seeds, admin UI, ...).
    """
  end

  defp render(template, assigns) do
    Enum.reduce(assigns, template, fn {key, value}, acc ->
      String.replace(acc, "__#{String.upcase(to_string(key))}__", to_string(value))
    end)
  end

  defp timestamp do
    {{y, m, d}, {hh, mm, ss}} = :calendar.universal_time()

    :io_lib.format("~4..0B~2..0B~2..0B~2..0B~2..0B~2..0B", [y, m, d, hh, mm, ss])
    |> IO.iodata_to_binary()
  end

  # Injected snippets

  defp verify_api_token_code do
    ~S'''
    @doc """
    Checks if the API token is valid and returns its underlying lookup query.

    The query returns the user found by the token, if any.

    The given token is valid if it matches its hashed counterpart in the
    database and the user email has not changed. This function also checks
    if the token is being used within #{@api_token_validity_in_days} days.
    """
    def verify_api_token_query(token) do
      case Base.url_decode64(token, padding: false) do
        {:ok, decoded_token} ->
          hashed_token = :crypto.hash(@hash_algorithm, decoded_token)

          query =
            from token in by_token_and_context_query(hashed_token, "api-token"),
              join: user in assoc(token, :user),
              where:
                token.inserted_at > ago(^@api_token_validity_in_days, "day") and
                  token.sent_to == user.email,
              select: user

          {:ok, query}

        :error ->
          :error
      end
    end
    '''
  end

  defp accounts_api_code do
    ~S'''
    @doc """
    Creates a new API token for a user.

    The token returned must be saved somewhere safe.
    This token cannot be recovered from the database.
    """
    def create_user_api_token(user) do
      {encoded_token, user_token} = UserToken.build_email_token(user, "api-token")
      Repo.insert!(user_token)
      encoded_token
    end

    @doc """
    Fetches the user by API token. Returns `{:ok, user}` or `:error`.
    """
    def fetch_user_by_api_token(token) do
      with {:ok, query} <- UserToken.verify_api_token_query(token),
           %User{} = user <- Repo.one(query) do
        {:ok, user}
      else
        _ -> :error
      end
    end
    '''
  end

  defp api_plug_code do
    ~S'''
    def fetch_current_scope_for_api_user(conn, _opts) do
      with [<<bearer::binary-size(6), " ", token::binary>>] <-
             get_req_header(conn, "authorization"),
           true <- String.downcase(bearer) == "bearer",
           {:ok, user} <- Accounts.fetch_user_by_api_token(token) do
        assign(conn, :current_scope, Accounts.Scope.for_user(user))
      else
        _ ->
          conn
          |> send_resp(:unauthorized, "Unauthorized")
          |> halt()
      end
    end
    '''
  end

  defp sso_handler_code do
    ~S'''
    def handle_event("sso", %{"user" => %{"provider" => provider}}, socket) do
      if provider in socket.assigns.sso_providers do
        {:noreply, redirect(socket, to: ~p"/auth/#{provider}")}
      else
        {:noreply, put_flash(socket, :error, "Choose a sign-in provider first.")}
      end
    end
    '''
  end

  defp sso_form_block do
    ~S'''
    <div :if={@sso_providers != []} class="divider">or</div>

    <.form
      :let={f}
      for={@sso_form}
      id="login_form_sso"
      phx-submit="sso"
    >
      <.input
        field={f[:provider]}
        type="select"
        label="Sign in with"
        options={@sso_providers}
        prompt="Choose a provider"
      />
      <.button class="btn btn-primary w-full">
        Continue <span aria-hidden="true">→</span>
      </.button>
    </.form>
    '''
  end

  # File templates

  defp migration do
    ~S'''
    defmodule __BASE__.Repo.Migrations.ExtendAuthWithRolesGroupsAndSso do
      use Ecto.Migration

      def change do
        alter table(:users) do
          add :role, :string, null: false, default: "user"
        end

        create table(:groups) do
          add :name, :string, null: false
          timestamps()
        end

        create unique_index(:groups, [:name])

        create table(:user_groups, primary_key: false) do
          add :user_id, references(:users, on_delete: :delete_all), null: false
          add :group_id, references(:groups, on_delete: :delete_all), null: false
        end

        create unique_index(:user_groups, [:user_id, :group_id])

        create table(:user_identities) do
          add :user_id, references(:users, on_delete: :delete_all), null: false
          add :provider, :string, null: false
          add :uid, :string, null: false
          add :tokens, :map
          timestamps()
        end

        create unique_index(:user_identities, [:provider, :uid])
      end
    end
    '''
  end

  defp group do
    ~S'''
    defmodule __BASE__.__CONTEXT__.Group do
      use Ecto.Schema
      import Ecto.Changeset

      schema "groups" do
        field :name, :string
        many_to_many :users, __BASE__.__CONTEXT__.User, join_through: "user_groups"
        timestamps()
      end

      def changeset(group, attrs) do
        group
        |> cast(attrs, [:name])
        |> validate_required([:name])
        |> unique_constraint(:name)
      end
    end
    '''
  end

  defp user_identity do
    ~S'''
    defmodule __BASE__.__CONTEXT__.UserIdentity do
      use Ecto.Schema

      schema "user_identities" do
        field :provider, :string
        field :uid, :string
        field :tokens, :map, default: %{}
        belongs_to :user, __BASE__.__CONTEXT__.User
        timestamps()
      end
    end
    '''
  end

  defp sso_context do
    ~S'''
    defmodule __BASE__.__CONTEXT__.SSO do
      @moduledoc """
      Find-or-create users from external identity providers and link provider
      identities to accounts. Called by __WEB__.SSOController after Assent
      completes its callback phase.
      """

      import Ecto.Query
      alias __BASE__.Repo
      alias __BASE__.__CONTEXT__.{User, UserIdentity}

      @doc "Names of the configured SSO providers (keys of config :__APP__, :sso_providers), as strings."
      def configured_providers do
        Application.get_env(:__APP__, :sso_providers, [])
        |> Keyword.keys()
        |> Enum.map(&to_string/1)
        |> Enum.sort()
      end

      @doc """
      Upserts the user for a provider identity.

      * If the identity exists, its user is returned.
      * Else, if the provider-verified email matches an existing user, the
        identity is linked to that account (only when the provider marked the
        email as verified).
      * Else, a new confirmed user is created and the identity is stored.

      Provider emails are trusted only when `info["email_verified"]` is
      present - unverified emails never match existing accounts.
      """
      def upsert_from_provider(provider, uid, info, tokens \\ %{}) do
        provider = to_string(provider)

        Repo.transaction(fn ->
          user =
            case get_identity_user(provider, uid) do
              %User{} = user -> user
              nil -> find_or_create_user!(email_from(info), info)
            end

          put_identity!(user, provider, uid, tokens)
          user
        end)
      end

      defp get_identity_user(provider, uid) do
        from(i in UserIdentity,
          join: u in User,
          on: u.id == i.user_id,
          where: i.provider == ^provider and i.uid == ^uid,
          select: u
        )
        |> Repo.one()
      end

      defp put_identity!(user, provider, uid, tokens) do
        %UserIdentity{}
        |> Ecto.Changeset.change(user_id: user.id, provider: provider, uid: uid, tokens: tokens)
        |> Repo.insert(on_conflict: :nothing, conflict_target: [:provider, :uid])
      end

      defp find_or_create_user!(nil, _info), do: Repo.rollback(:missing_email)

      defp find_or_create_user!(email, info) do
        verified? = info["email_verified"] in [true, "true"]

        case Repo.get_by(User, email: email) do
          %User{} = user ->
            if verified?, do: user, else: Repo.rollback(:email_not_verified)

          nil ->
            case Repo.insert(user_changeset(email)) do
              {:ok, user} ->
                user

              {:error, _changeset} ->
                # Lost a race with a concurrent sign-up; reuse the winner.
                case Repo.get_by(User, email: email) do
                  %User{} = user -> user
                  nil -> Repo.rollback(:missing_email)
                end
            end
        end
      end

      defp user_changeset(email) do
        changeset =
          %User{}
          |> Ecto.Changeset.cast(
            %{
              email: email,
              confirmed_at: DateTime.utc_now() |> DateTime.truncate(:second),
              role: "user"
            },
            [:email, :confirmed_at, :role]
          )
          |> Ecto.Changeset.unique_constraint(:email)

        if User.__schema__(:type, :hashed_password) do
          # Password-less SSO account: store an unusable random hash so the
          # column constraint holds and no password can ever match.
          Ecto.Changeset.put_change(changeset, :hashed_password, unusable_hash())
        else
          changeset
        end
      end

      defp unusable_hash do
        :crypto.strong_rand_bytes(32) |> Base.encode64(padding: false)
      end

      defp email_from(%{"email" => email}) when is_binary(email), do: String.downcase(email)
      defp email_from(_), do: nil
    end
    '''
  end

  defp sso_controller do
    ~S'''
    defmodule __WEB__.SSOController do
      @moduledoc """
      Generic Assent request/callback controller for all providers configured
      under `config :__APP__, :sso_providers`.

      Routes (added by the generator):

          get "/auth/:provider", __WEB__.SSOController, :request
          get "/auth/:provider/callback", __WEB__.SSOController, :callback
      """

      use __WEB__, :controller

      alias __BASE__.__CONTEXT__
      alias __WEB__.UserAuth

      def request(conn, %{"provider" => provider}) do
        case provider_config(conn, provider) do
          {:ok, config} ->
            strategy = config[:strategy]

            case strategy.authorize_url(config) do
              {:ok, %{url: url, session_params: session_params}} ->
                conn
                |> put_session(:assent_session_params, session_params)
                |> redirect(external: url)

              {:error, reason} ->
                send_error(conn, provider, reason)
            end

          {:error, reason} ->
            send_error(conn, provider, reason)
        end
      end

      def callback(conn, %{"provider" => provider} = params) do
        session_params = get_session(conn, :assent_session_params) || %{}

        case provider_config(conn, provider) do
          {:ok, config} ->
            strategy = config[:strategy]
            config = Keyword.put(config, :session_params, session_params)

            case strategy.callback(config, params) do
              {:ok, %{user: user_info, token: token}} ->
                uid = user_info["sub"] || user_info["id"] || user_info["uid"]

                case __CONTEXT__.SSO.upsert_from_provider(provider, uid, user_info, token || %{}) do
                  {:ok, user} ->
                    conn
                    |> delete_session(:assent_session_params)
                    |> put_flash(:info, "Signed in with " <> provider <> ".")
                    |> UserAuth.log_in_user(user)

                  {:error, reason} ->
                    send_error(conn, provider, reason)
                end

              {:error, reason} ->
                send_error(conn, provider, reason)
            end

          {:error, reason} ->
            send_error(conn, provider, reason)
        end
      end

      defp send_error(conn, provider, reason) do
        conn
        |> delete_session(:assent_session_params)
        |> put_flash(:error, "Sign in with " <> provider <> " failed: " <> inspect(reason))
        |> redirect(to: ~p"/users/log-in")
      end

      defp provider_config(conn, provider) do
        providers = Application.get_env(:__APP__, :sso_providers, [])

        case Enum.find(providers, fn {key, _config} -> to_string(key) == provider end) do
          nil ->
            {:error, :unknown_provider}

          {_key, config} ->
            strategy = config[:strategy] || Assent.Strategy.OIDC

            {:ok,
             config
             |> Keyword.put(:strategy, strategy)
             |> Keyword.put(:redirect_uri, url(conn, ~p"/auth/#{provider}/callback"))}
        end
      end
    end
    '''
  end

  defp scope do
    ~S'''
    defmodule __BASE__.__CONTEXT__.Scope do
      @moduledoc """
      Request scope enriched with authorization data.

      Carries the current `user` alongside `role` (the user's role) and
      `group_ids` (ids of the groups the user belongs to, loaded with a
      single query). Keep authorization checks against these fields:
      `scope.role`, `scope.group_ids`. Returns nil when there is no user,
      so `@current_scope` checks in templates keep working.
      """

      import Ecto.Query
      alias __BASE__.Repo
      alias __BASE__.__CONTEXT__.{Group, User}

      defstruct [:user, :role, :group_ids]

      @doc """
      Builds a scope for the given user, enriched with role and group ids.
      Returns nil if no user is given, exactly like the stock generator.
      """
      def for_user(%User{} = user) do
        %__MODULE__{user: user, role: user.role, group_ids: group_ids(user)}
      end

      def for_user(nil), do: nil

      defp group_ids(%User{} = user) do
        Repo.all(
          from g in Group,
            join: ug in "user_groups",
            on: ug.group_id == g.id,
            where: ug.user_id == ^user.id,
            select: g.id
        )
      end
    end
    '''
  end
end
