{-# LANGUAGE BlockArguments        #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DerivingVia           #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GHC2024               #-}
{-# LANGUAGE NoFieldSelectors      #-}
{-# LANGUAGE OverloadedRecordDot   #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE TypeApplications      #-}
module Todo
  ( Todo(..)
  , htmx
  , todoRoutes
  , getTodosPage
  , getTodoListPartial
  , addTodo
  , toggleTodo
  , deleteTodo
  , clearCompleted
  , editTodoForm
  , updateTodo
  , getTodosSession
  , getTodoSession
  , addTodoSession
  , toggleTodoSession
  , deleteTodoSession
  , clearCompletedSession
  , updateTodoTitleSession
  , todoPage
  , todoListSection
  , todoItem
  ) where

import Data.Text qualified as T
import Data.Vector qualified as V
import Optics
import Prelude hiding (id)

import Colog
import Database
import Debug.Breakpoint
import Hasql.TH
import Htmx
import Network.Wai (Middleware, rawPathInfo, requestMethod)
import Web.Twain as Twain

data Todo = Todo { id :: Int64, title :: Text, completed :: Bool }
  deriving (Eq, Show)

normalizeTitle :: Text -> Text
normalizeTitle = T.strip

normalizeTitleKey :: Text -> Text
normalizeTitleKey = T.toCaseFold . normalizeTitle

listSwap :: Text
listSwap = "outerMorph"

searchInputInclude :: Text
searchInputInclude = "#todo-input:not(:invalid)"

listStateInclude :: Text
listStateInclude = "#todo-list-form, " <> searchInputInclude

addFormStateInclude :: Text
addFormStateInclude = "#todo-list-form [name='filter'], #todo-input"

render :: Html () -> ResponderM a
render = Twain.send . Twain.html . renderBS

htmx :: Html () -> Html ()
htmx body = [hsx|
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>My Simple HTML Page</title>
      <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
      <style>
        @keyframes todo-flash {
          0% { background-color: color-mix(in srgb, var(--pico-primary), transparent 78%); }
          100% { background-color: transparent; }
        }
        .todo-highlight {
          animation: todo-flash 1.5s ease-out;
        }
      </style>
      <script defer src="https://cdn.jsdelivr.net/npm/htmx.org@next"></script>
    </head>
    <body>
      <main class="container">
      {body}
      </main>
    </body>
  </html>
|]

runDbOr500 :: Pool -> Session a -> ResponderM a
runDbOr500 pool session = do
  res <- liftIO $ runDb pool session
  case res of
    Left err ->
      send
        $ Twain.status (toEnum 500)
        $ Twain.html
        $ renderBS [hsx|<div>Database Error: {T.pack (show err)}</div>|]
    Right a -> pure a

todoRoutes :: Pool -> [Middleware]
todoRoutes pool =
  [ Twain.get    "/todos"       (getTodosPage pool)
  , Twain.get    "/todos/list"  (getTodoListPartial pool)
  , Twain.post   "/todos"       (addTodo pool)
  , Twain.post   "/todos/clear" (clearCompleted pool)
  , Twain.patch  "/todos/:id"   (toggleTodo pool)
  , Twain.delete "/todos/:id"   (deleteTodo pool)
  , Twain.get    "/todos/:id/edit" (editTodoForm pool)
  , Twain.put    "/todos/:id"   (updateTodo pool)
  ]

getTodosSession :: Session [Todo]
getTodosSession = do
  V.toList . V.map (\(id', title', completed') -> Todo id' title' completed') <$> statement ()
    [vectorStatement|
      select id :: int8, title :: text, completed :: bool from todos order by id
    |]

getTodosPage :: Pool -> ResponderM a
getTodosPage pool = do
  items <- runDbOr500 pool getTodosSession
  -- breakpointIO
  render $ todoPage items "all"

getTodoListPartial :: Pool -> ResponderM a
getTodoListPartial pool = do
  items   <- runDbOr500 pool getTodosSession
  filter_ <- Twain.paramMaybe @Text "filter"
  search_ <- Twain.paramMaybe @Text "title"
  -- breakpointIO
  render $ todoListSection items (fromMaybe "" search_) (fromMaybe "all" filter_)

addTodo :: Pool -> ResponderM a
addTodo pool = do
  title' <- Twain.param @Text "title"
  filter_ <- Twain.paramMaybe @Text "filter"
  let normalizedTitle = normalizeTitle title'
  isDuplicate <- runDbOr500 pool (todoTitleExistsSession normalizedTitle)
  duplicateTodo <-
    if isDuplicate
      then runDbOr500 pool (getTodoByTitleSession normalizedTitle)
      else pure Nothing
  unless (T.null normalizedTitle || isDuplicate) $
    runDbOr500 pool (addTodoSession normalizedTitle)
  items <- runDbOr500 pool getTodosSession
  let f = fromMaybe "all" filter_
  -- breakpointIO
  render do
    todoAddForm
    todoListSectionHighlightedOob items "" f (fmap (.id) duplicateTodo) True

toggleTodo :: Pool -> ResponderM a
toggleTodo pool = do
  i <- Twain.param @Int64 "id"
  filter_ <- Twain.paramMaybe @Text "filter"
  search_ <- Twain.paramMaybe @Text "title"
  runDbOr500 pool (toggleTodoSession i)
  items <- runDbOr500 pool getTodosSession
  -- breakpointIO
  render $ todoListSection items (fromMaybe "" search_) (fromMaybe "all" filter_)

deleteTodo :: Pool -> ResponderM a
deleteTodo pool = do
  i <- Twain.param @Int64 "id"
  filter_ <- Twain.paramMaybe @Text "filter"
  search_ <- Twain.paramMaybe @Text "title"
  runDbOr500 pool (deleteTodoSession i)
  items <- runDbOr500 pool getTodosSession
  -- breakpointIO
  render $ todoListSection items (fromMaybe "" search_) (fromMaybe "all" filter_)

clearCompleted :: Pool -> ResponderM a
clearCompleted pool = do
  filter_ <- Twain.paramMaybe @Text "filter"
  search_ <- Twain.paramMaybe @Text "title"
  runDbOr500 pool clearCompletedSession
  items <- runDbOr500 pool getTodosSession
  -- breakpointIO
  render $ todoListSection items (fromMaybe "" search_) (fromMaybe "all" filter_)

editTodoForm :: Pool -> ResponderM a
editTodoForm pool = do
  i <- Twain.param @Int64 "id"
  mTodo <- runDbOr500 pool (getTodoSession i)
  -- breakpointIO
  case mTodo of
    Just todo -> render [hsx|
      <li style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0; border-bottom: 1px solid var(--pico-muted-border-color);"
          id={"todo-item-" <> show todo.id :: Text}>
        <form hx-put={"/todos/" <> show todo.id :: Text} hx-include={listStateInclude} hx-target="#todo-list" hx-swap={listSwap} style="width: 100%; display: flex; margin-bottom: 0;">
          <input type="text" name="edit-title" value={todo.title} required autofocus style="flex: 1; margin-bottom: 0;">
          <button type="submit" class="outline" style="margin-left: 0.5rem; width: auto; padding: 0.25rem 0.5rem; margin-bottom: 0;">Save</button>
        </form>
      </li>
    |]
    Nothing -> send $ Twain.status (toEnum 404) $ Twain.html "Todo not found"

updateTodo :: Pool -> ResponderM a
updateTodo pool = do
  i <- Twain.param @Int64 "id"
  editTitle_ <- Twain.paramMaybe @Text "edit-title"
  titleParam <- Twain.paramMaybe @Text "title"
  filter_ <- Twain.paramMaybe @Text "filter"
  let title' = fromMaybe "" (editTitle_ <|> titleParam)
  let search_ = titleParam
  let normalizedTitle = normalizeTitle title'
  isDuplicate <- runDbOr500 pool (todoTitleExistsExceptSession i normalizedTitle)
  unless (T.null normalizedTitle || isDuplicate) $
    runDbOr500 pool (updateTodoTitleSession i normalizedTitle)
  items <- runDbOr500 pool getTodosSession
  -- breakpointIO
  render $ todoListSection items (fromMaybe "" search_) (fromMaybe "all" filter_)

addTodoSession :: Text -> Session ()
addTodoSession title' = statement title'
  [resultlessStatement| insert into todos (title) values ($1 :: text) |]

todoTitleExistsSession :: Text -> Session Bool
todoTitleExistsSession title' = do
  res <- statement title'
    [maybeStatement|
      select 1 :: int4
      from todos
      where lower(btrim(title)) = lower(btrim($1 :: text))
      limit 1
    |]
  pure $ isJust res

getTodoByTitleSession :: Text -> Session (Maybe Todo)
getTodoByTitleSession title' = do
  fmap (\(id', title'', completed') -> Todo id' title'' completed') <$> statement title'
    [maybeStatement|
      select id :: int8, title :: text, completed :: bool
      from todos
      where lower(btrim(title)) = lower(btrim($1 :: text))
      order by id
      limit 1
    |]

todoTitleExistsExceptSession :: Int64 -> Text -> Session Bool
todoTitleExistsExceptSession id' title' = do
  res <- statement (id', title')
    [maybeStatement|
      select 1 :: int4
      from todos
      where id <> $1 :: int8
        and lower(btrim(title)) = lower(btrim($2 :: text))
      limit 1
    |]
  pure $ isJust res

toggleTodoSession :: Int64 -> Session ()
toggleTodoSession id' = statement id'
  [resultlessStatement| update todos set completed = not completed where id = $1 :: int8 |]

deleteTodoSession :: Int64 -> Session ()
deleteTodoSession id' = statement id'
  [resultlessStatement| delete from todos where id = $1 :: int8 |]

clearCompletedSession :: Session ()
clearCompletedSession = statement ()
  [resultlessStatement| delete from todos where completed = true |]

getTodoSession :: Int64 -> Session (Maybe Todo)
getTodoSession id' = do
  fmap (\(id'', title', completed') -> Todo id'' title' completed') <$> statement id'
    [maybeStatement|
      select id :: int8, title :: text, completed :: bool from todos where id = $1 :: int8
    |]

updateTodoTitleSession :: Int64 -> Text -> Session ()
updateTodoTitleSession id' title' = statement (title', id')
  [resultlessStatement| update todos set title = $1 :: text where id = $2 :: int8 |]

todoPage :: [Todo] -> Text -> Html ()
todoPage items filterBy = htmx [hsx|
  <article>
    <h1>Todos</h1>
    {todoAddForm}
    <nav>
      <ul>
        <li><a href="#" hx-get="/todos/list?filter=all" hx-include={searchInputInclude} hx-target="#todo-list" hx-swap={listSwap}>All</a></li>
        <li><a href="#" hx-get="/todos/list?filter=active" hx-include={searchInputInclude} hx-target="#todo-list" hx-swap={listSwap}>Active</a></li>
        <li><a href="#" hx-get="/todos/list?filter=completed" hx-include={searchInputInclude} hx-target="#todo-list" hx-swap={listSwap}>Completed</a></li>
      </ul>
    </nav>
    {todoListSection items "" filterBy}
  </article>
|]

todoAddForm :: Html ()
todoAddForm = [hsx|
  <form id="add-form" hx-post="/todos" hx-target="#add-form" hx-swap="outerHTML" hx-include="#todo-list-form [name='filter']">
    <fieldset role="group">
      <input id="todo-input" name="title" placeholder="What needs to be done?" autocomplete="off" required autofocus
             hx-get="/todos/list" hx-trigger="input changed delay:500ms"
             hx-include={addFormStateInclude}
             hx-target="#todo-list" hx-swap={listSwap} hx-sync="closest form:abort">
      <button type="submit">Add</button>
    </fieldset>
  </form>
|]

todoListSection :: [Todo] -> Text -> Text -> Html ()
todoListSection items searchQ filterBy = todoListSectionHighlighted items searchQ filterBy Nothing

todoListSectionHighlighted :: [Todo] -> Text -> Text -> Maybe Int64 -> Html ()
todoListSectionHighlighted items searchQ filterBy highlightedTodoId =
  todoListSectionHighlightedOob items searchQ filterBy highlightedTodoId False

todoListSectionHighlightedOob :: [Todo] -> Text -> Text -> Maybe Int64 -> Bool -> Html ()
todoListSectionHighlightedOob items searchQ filterBy highlightedTodoId oob =
  if oob
    then [hsx|<section id="todo-list" hx-swap-oob={listSwap}>{todoListForm}</section>|]
    else [hsx|<section id="todo-list">{todoListForm}</section>|]
  where
    todoListForm = [hsx|
    <form id="todo-list-form">
      <input type="hidden" name="filter" value={filterBy}>
      <ul style="list-style: none; padding: 0;">
        {mapM_ (todoItemHighlighted highlightedTodoId) matched}
      </ul>
      <footer style="display: flex; justify-content: space-between; align-items: center;">
        <small>{activeCountText}</small>
        {clearButton}
      </footer>
    </form>
  |]
    searched = filter (todoMatchesSearch searchQ) items
    matched = case filterBy of
      "active"    -> filter (not . (.completed)) searched
      "completed" -> filter (.completed) searched
      _           -> searched
    activeCount = length $ filter (not . (.completed)) items
    activeCountText :: Text
    activeCountText = show activeCount <> " item" <> (if activeCount == 1 then "" else "s") <> " left"
    completedCount = length $ filter (.completed) items
    completedCountText :: Text
    completedCountText = show completedCount
    clearButton :: Html ()
    clearButton
      | completedCount > 0 = [hsx|
          <button class="outline" hx-post="/todos/clear" hx-include={listStateInclude} hx-target="#todo-list" hx-swap={listSwap}>
            Clear completed ({completedCountText})
          </button>
        |]
      | otherwise = mempty

todoMatchesSearch :: Text -> Todo -> Bool
todoMatchesSearch searchQ todo =
  null queryTokens || queryTokens `prefixSubsequenceOf` titleTokens
  where
    queryTokens = searchTokens searchQ
    titleTokens = searchTokens todo.title

searchTokens :: Text -> [Text]
searchTokens = T.words . T.replace "+" " " . normalizeTitleKey

prefixSubsequenceOf :: [Text] -> [Text] -> Bool
prefixSubsequenceOf [] _ = True
prefixSubsequenceOf _ [] = False
prefixSubsequenceOf query@(q:qs) (title:titleRest)
  | q `T.isPrefixOf` title = qs `prefixSubsequenceOf` titleRest
  | otherwise = query `prefixSubsequenceOf` titleRest

todoItem :: Todo -> Html ()
todoItem = todoItemHighlighted Nothing

todoItemHighlighted :: Maybe Int64 -> Todo -> Html ()
todoItemHighlighted highlightedTodoId todo = [hsx|
  <li style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0; border-bottom: 1px solid var(--pico-muted-border-color);"
      class={classes}
      id={"todo-item-" <> show todo.id :: Text}>
    {completed}
    {titleHtml}
    <button class="outline secondary" hx-delete={deletePath} hx-include={listStateInclude} hx-target="#todo-list" hx-swap={listSwap} hx-confirm="Delete this todo?"
            style="margin-left: auto; width: auto; padding: 0.25rem 0.5rem; margin-bottom: 0;">
      ✕
    </button>
  </li>
|]
  where
    patchPath  = "/todos/" <> show todo.id :: Text
    deletePath = "/todos/" <> show todo.id :: Text
    editPath   = "/todos/" <> show todo.id <> "/edit" :: Text
    classes :: Text
    classes
      | Just todo.id == highlightedTodoId = "todo-highlight"
      | otherwise = ""
    completed :: Html ()
    completed
      | todo.completed = [hsx|<input type="checkbox" checked hx-patch={patchPath} hx-include={listStateInclude} hx-target="#todo-list" hx-swap={listSwap} style="margin-bottom: 0;">|]
      | otherwise      = [hsx|<input type="checkbox" hx-patch={patchPath} hx-include={listStateInclude} hx-target="#todo-list" hx-swap={listSwap} style="margin-bottom: 0;">|]
    titleHtml :: Html ()
    titleHtml
      | todo.completed = [hsx|<s style="opacity: 0.5;" hx-get={editPath} hx-trigger="dblclick" hx-target={"#todo-item-" <> show todo.id :: Text} hx-swap={listSwap}>{todo.title}</s>|]
      | otherwise      = [hsx|<span hx-get={editPath} hx-trigger="dblclick" hx-target={"#todo-item-" <> show todo.id :: Text} hx-swap={listSwap}>{todo.title}</span>|]
