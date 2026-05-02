# Servant Todo Route Migration Plan

## Purpose

Migrate the Todo HTTP boundary from Twain middleware routes to Servant API
types so the app can expose one type-checked Todo route surface that serves
HTML to htmx and JSON to programmatic clients through HTTP content negotiation.

The current file is `hs/src/Todo.hs` rather than `hs/Todo.hs`.

## Current State

- `hs/src/App.hs` assembles the WAI application and serves the root route,
  `GET /htmx/hello/:name`, Todo routes, and an embedded WAI static asset app at
  `/assets`.
- `hs/src/Http.hs` owns the Servant HTML content type, reusable page shell,
  and static asset script tags.
- `hs/src/Htmx.hs` owns only the HSX quasiquoter setup and Lucid re-export.
- `hs/src/Todo.hs` owns the Todo domain type, Hasql sessions, Twain route
  declarations, Twain request parsing, Twain response rendering, and Lucid/HSX
  HTML rendering.
- The htmx UI depends on the existing root-level routes:
  - `GET /todos`
  - `GET /todos/list?filter=...&title=...`
  - `POST /todos`
  - `POST /todos/clear`
  - `PATCH /todos/:id`
  - `DELETE /todos/:id`
  - `GET /todos/:id/edit`
  - `PUT /todos/:id`
- Existing tests in `hs/src/TodoTest.hs` assert those paths, methods, htmx
  attributes, and core Todo behavior.
- There is no JSON Todo API today.
- There is no existing `CONTEXT.md`, `CONTEXT-MAP.md`, or ADR tree. This
  migration is an implementation architecture change, not a resolved
  domain-language change, so no domain context file is needed yet.

## Research Decision

Use a single `/todos` route surface with Servant content negotiation.

Native htmx form posts are preferred for the Todo HTML UI.

- htmx already submits standard forms as
  `application/x-www-form-urlencoded`.
- htmx 4 sends an explicit `Accept: text/html` request header, so htmx requests
  naturally select the HTML representation.
- Avoiding a custom JSON body extension keeps the template simpler and closer
  to htmx defaults.

The Servant docs support the matching server-side model:

- `ReqBody` selects a decoder from the request `Content-Type`.
- A Servant endpoint can list multiple response content types, such as
  `Get '[JSON, HTML] ...`, and Servant selects the renderer from `Accept`.
- `JSON`, `PlainText`, `FormUrlEncoded`, and `OctetStream` are built in; custom
  HTML rendering is supplied with an `Accept` and `MimeRender` instance.
- Servant's record-style APIs with `NamedRoutes` avoid endpoint-order mistakes
  from long `:<|>` chains and produce better field-specific GHC errors.

Decision:

- htmx Todo mutation forms should send native form-encoded request bodies.
- htmx Todo responses should remain HTML pages/fragments.
- Programmatic clients should use the same routes with JSON request bodies and
  `Accept: application/json`.
- Servant mutation endpoints should accept both `FormUrlEncoded` and `JSON`
  request bodies into the same typed request DTOs.
- Use record-style Servant APIs with `NamedRoutes` for the Todo route tree.
- Do not create separate `/api/todos` routes unless content negotiation fails in
  practice.

## Recommended Direction

Preserve the current `/todos` paths and methods, but make each route a Servant
route whose request and response content types describe the real HTTP contract.
Before migrating Todo routes, introduce a small app startup Module so the
template has a clear reusable shell.
Create a small `Http` Module for HTML response rendering and htmx-specific
page support while keeping `Htmx.hs` focused on HSX setup.

Rationale:

- htmx 4 can send form data as JSON through its Data API extensions.
- htmx 4 already asks for HTML responses, so Servant response negotiation can
  return HTML to htmx and JSON to API clients.
- One route tree avoids duplicated business logic and duplicated route tests.
- Record-style `NamedRoutes` avoids order-sensitive `:<|>` handler wiring for a
  route set that already has page, list, add, clear, item mutation, edit, and
  update endpoints.
- An app startup Module concentrates process-independent webapp assembly in one
  place. `Main` should only acquire resources and run Warp/Rapid.
- Keeping `Htmx.hs` narrow avoids Template Haskell stage-restriction problems
  and keeps the template simple: HSX setup is in `Htmx`, HTTP/content
  negotiation/page-shell concerns are in `Http`.
- The API remains more REST-shaped than a separate `/api` namespace because the
  resource URL is stable and representation is negotiated by headers.
- The implementation still needs explicit view/result types so a single handler
  value can render as either HTML or JSON.

## Template Startup Shape

Introduce an `App` Module before the Todo route migration.

Target shape:

```haskell
module App
  ( app
  , appRoutes
  , logRequest
  , index
  , page404
  ) where
```

Responsibilities:

- Build the WAI `Application` from already-acquired resources.
- Mount the root route, feature routes, request logging, and 404 behavior.
- Keep route assembly usable by both production startup and tests.
- Hide route-composition details from `Main`.

`Main` should become process startup only:

```haskell
main :: IO ()
main =
  bracket acquirePool releasePool \pool ->
    rapid 0 \r -> restart r "server" $
      Wai.run 8080 (app pool)
```

`TodoTest` should import `App (app)` instead of `Main (app)`.

Deletion test:

- Deleting `Main` should remove only executable startup.
- The webapp should still be testable through `App.app`.
- Deleting `App` should force route assembly knowledge back into `Main` and
  `TodoTest`, so the Module is earning its keep.

## Web Foundation Shape

Keep the existing `Htmx` Module as-is and introduce a small `Http` Module.

Target shape:

```haskell
module Http
  ( HTML
  , pageShell
  ) where
```

Responsibilities:

- Own Servant's `HTML` content type and `MimeRender HTML (Html ())`.
- Own the reusable page shell used by sample features.

`Htmx.hs` remains responsible for:

- HSX quasiquoter setup.
- Lucid re-export.

Non-goals:

- Do not introduce a broad HTTP abstraction.
- Do not move Todo-specific fragments into `Htmx`.
- Do not introduce a second rendering library or a second page-shell Module.

Deletion test:

- Deleting `Http` should force Servant `HTML`, page shell, and local htmx JSON
  response support back into `App` and feature Modules.
- Deleting `Htmx` should force only HSX setup back into feature Modules.

## Target Route Shape

Use record-style `NamedRoutes` with one `TodoAPI` and one `todoServer`.

```haskell
data TodoAPI mode = TodoAPI
  { page
      :: mode :- "todos"
      :> QueryParam "filter" Text
      :> QueryParam "title" Text
      :> Get '[HTML, JSON] TodosView

  , list
      :: mode :- "todos" :> "list"
      :> QueryParam "filter" Text
      :> QueryParam "title" Text
      :> Get '[HTML, JSON] TodoListView

  , add
      :: mode :- "todos"
      :> ReqBody '[JSON] AddTodoRequest
      :> Post '[HTML, JSON] TodoMutationView

  , clear
      :: mode :- "todos" :> "clear"
      :> ReqBody '[JSON] TodoListState
      :> Post '[HTML, JSON] TodoMutationView

  , item
      :: mode :- "todos"
      :> Capture "id" Int64
      :> NamedRoutes TodoItemAPI
  }
  deriving stock Generic

data TodoItemAPI mode = TodoItemAPI
  { toggle
      :: mode :- ReqBody '[JSON] TodoListState
      :> Patch '[HTML, JSON] TodoMutationView

  , delete
      :: mode :- ReqBody '[JSON] TodoListState
      :> Delete '[HTML, JSON] TodoMutationView

  , edit
      :: mode :- "edit"
      :> Get '[HTML, JSON] TodoEditView

  , update
      :: mode :- ReqBody '[JSON] UpdateTodoRequest
      :> Put '[HTML, JSON] TodoMutationView
  }
  deriving stock Generic

type TodoRoutes = NamedRoutes TodoAPI
```

Notes:

- `HTML` is response-only. Do not define an HTML request decoder.
- `AddTodoRequest` includes `title` and list state fields needed to re-render
  the current list.
- `UpdateTodoRequest` includes the new title plus list state fields.
- `TodoListState` includes optional `filter` and `title` search state for
  mutation responses.
- Use `ReqBody '[FormUrlEncoded, JSON] ...` for mutation request DTOs.
- htmx uses the `FormUrlEncoded` decoder.
- API clients use the `JSON` decoder.
- If empty request bodies for `PATCH` or `DELETE` become a problem for
  external clients, investigate optional request bodies or move list state to
  query parameters.

## Representation Types

Use explicit representation/view types rather than returning raw `[Todo]` or
`Html ()` directly from handlers.

```haskell
data TodosView = TodosView
  { todos :: [Todo]
  , filter :: Text
  , title :: Text
  }

data TodoListView = TodoListView
  { todos :: [Todo]
  , filter :: Text
  , title :: Text
  , highlightedTodoId :: Maybe Int64
  , outOfBand :: Bool
  }

data TodoMutationView = TodoMutationView
  { todos :: [Todo]
  , filter :: Text
  , title :: Text
  , mutation :: TodoMutationStatus
  }
```

Each view type needs:

- `ToJSON` for `JSON`.
- `MimeRender HTML ...` for HTML pages/fragments.

This keeps one handler per route while still allowing representation-specific
rendering.

## htmx Changes

1. Load htmx 4 explicitly instead of `@next` once the target version is chosen.
2. Use native htmx form submission for mutation requests.
   - Do not load `form-json.js`.
   - Do not add `data-hx-json` or `hx-ext` attributes.
   - Let htmx send `application/x-www-form-urlencoded` bodies.
3. Keep htmx response negotiation unchanged. htmx 4 sends `Accept: text/html`,
   which selects the HTML renderer.
4. Preserve `hx-target`, `hx-swap`, `hx-include`, and out-of-band list
   replacement behavior.
5. Keep form field names aligned with request DTO `FromForm` instances:
   - Use `title` for add and search.
   - Accept `edit-title` and `title` for update.

## Implementation Steps

1. Introduce an app startup Module.
   - Add `hs/src/App.hs`.
   - Move `app`, route assembly, `logRequest`, `index`, and `page404` out of
     `Main.hs`.
   - Leave `main` in `Main.hs` as process startup only.
   - Update `hs/src/TodoTest.hs` to import `App (app)` instead of `Main (app)`.
   - This is the first template-oriented deepening step: startup concerns become
     local and reusable.

2. Add `hs/src/Http.hs` as the web foundation Module.
   - Move `data HTML`, `Accept HTML`, and `MimeRender HTML (Html ())` out of
     `Main.hs` into `hs/src/Http.hs`.
   - Move the reusable page shell currently named `htmx` out of `Todo.hs` into
     `Http.hs` and rename it to `pageShell`.
   - Keep Todo-specific rendering in `Todo.hs`.
   - Keep `Htmx.hs` as the HSX quasiquoter Module; do not add custom htmx
     attributes there for this migration.
   - Add the local htmx v4 JSON-body script helper in `Http.hs`, either as a
     rendered `Html ()` block or a small function used by `pageShell`.
   - Keep `renderBS` as the single HTML serialization path.

3. Add request DTOs and representation DTOs.
   - `AddTodoRequest`
   - `UpdateTodoRequest`
   - `TodoListState`
   - `TodosView`
   - `TodoListView`
   - `TodoEditView`
   - `TodoMutationView`
   - `TodoMutationStatus`

4. Add JSON instances.
   - `FromJSON` for request DTOs.
   - `ToJSON` for view/result DTOs.
   - Keep `Todo` JSON exposure deliberate; either give `Todo` a `ToJSON`
     instance or map it to a `TodoResponse`.

5. Add HTML render instances.
   - `MimeRender HTML TodosView` renders the full page via `todoPage`.
   - `MimeRender HTML TodoListView` renders `todoListSection` or highlighted
     out-of-band sections.
   - `MimeRender HTML TodoEditView` renders the edit form or throws 404 before
     rendering.
   - `MimeRender HTML TodoMutationView` renders the correct htmx fragment for
     the mutation result.

6. Convert shared mutation logic to return values instead of sending Twain
   responses.
   - Extract helper functions for list retrieval, filtering/search state,
     create, update, toggle, delete, and clear-completed.
   - Run database actions in `Handler` via `liftIO`.
   - Convert database failures to `throwError err500`.
   - Convert missing Todo edit form to `throwError err404`.

7. Define and serve record-style `TodoAPI`.
   - `data TodoAPI mode = ... deriving stock Generic`
   - `data TodoItemAPI mode = ... deriving stock Generic`
   - `type TodoRoutes = NamedRoutes TodoAPI`
   - `todoAPI :: Proxy TodoRoutes`
   - `todoServer :: Pool -> TodoAPI AsServer`
   - `todoItemServer :: Pool -> Int64 -> TodoItemAPI AsServer`
   - Replace `todoRoutes pool` with `serve todoAPI (todoServer pool)` inside
     the app route assembly.
   - The target end state for this migration is no `Web.Twain` import in
     `hs/src/Todo.hs`.

8. Keep the root route simple during migration.
   - `GET /` can remain Twain in `Main.hs` temporarily.
   - Alternatively move it to Servant after Todo routes compile.

9. Extend tests.
   - Existing HTML tests should continue to hit the same paths.
   - Update HTML mutation tests to send JSON request bodies once htmx does.
   - Add JSON negotiation tests on the same paths:
     - `GET /todos` with `Accept: application/json`
     - `GET /todos/list` with `Accept: application/json`
     - `POST /todos` with JSON body and `Accept: application/json`
     - duplicate create
     - empty-title create
     - `PUT /todos/:id`
     - duplicate update
     - `PATCH /todos/:id`
     - `DELETE /todos/:id`
     - `POST /todos/clear`
   - Assert status, `Content-Type`, and JSON shape.

10. Remove obsolete Twain Todo code.
- Delete `todoRoutes`.
   - Delete `ResponderM`-specific helpers from `Todo.hs`.
   - Keep Twain in `Main.hs` only if the root index and 404 stay Twain-based.

## Verification

- Do not run `cabal`, `stack`, or `make`; `hs/AGENTS.md` forbids them.
- After edits, read `hs/ghcid.txt`.
- Use the existing ghciwatch feedback loop.
- If route behavior changes, update `hs/src/TodoTest.hs` only after deciding the new
  behavior is intentional.

## Risks

- Native form posts are less expressive than JSON for nested data, but Todo
  mutations are flat and fit `application/x-www-form-urlencoded` well.
- Servant can negotiate response representations cleanly, but request-body and
  response-body negotiation must share one Haskell return type per endpoint.
  That is why this plan introduces representation/view types.
- `NamedRoutes` adds a small amount of `Generic`/`mode :-` syntax, but that
  cost is justified here because it avoids order-sensitive handler assembly.
- `PATCH` and `DELETE` bodies are legal but less common. If external clients
  object to sending `{}` or list state, use optional request bodies or query
  parameters for state.
- The current duplicate handling is UI-specific. JSON responses need an explicit
  `TodoMutationStatus` contract rather than inferring status from highlighted
  HTML.
- The same endpoint accepts both `FormUrlEncoded` and `JSON`; keep route tests
  for both so one representation does not regress silently.

## First Unresolved Decision

Should any Todo mutation route move list state from request bodies to query
parameters?

Recommended answer: not now. Keeping state in the typed request DTO preserves a
single handler contract for form and JSON clients.
