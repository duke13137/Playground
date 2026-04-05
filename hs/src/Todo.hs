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
  -- breakpointM
  render $ todoPage items "all"

getTodoListPartial :: Pool -> ResponderM a
getTodoListPartial pool = do
  items   <- runDbOr500 pool getTodosSession
  filter_ <- Twain.paramMaybe @Text "filter"
  search_ <- Twain.paramMaybe @Text "search"
  -- breakpointM
  render $ todoListSection items (fromMaybe "" search_) (fromMaybe "all" filter_)

addTodo :: Pool -> ResponderM a
addTodo pool = do
  title' <- Twain.param @Text "title"
  filter_ <- Twain.paramMaybe @Text "filter"
  search_ <- Twain.paramMaybe @Text "search"
  runDbOr500 pool (addTodoSession title')
  items <- runDbOr500 pool getTodosSession
  let f = fromMaybe "all" filter_
  let s = fromMaybe "" search_
  -- breakpointM
  render do
    todoListSection items s f
    [hsx|<input id="todo-input" name="title" placeholder="What needs to be done?" required autofocus hx-swap-oob="true">|]

toggleTodo :: Pool -> ResponderM a
toggleTodo pool = do
  i <- Twain.param @Int64 "id"
  filter_ <- Twain.paramMaybe @Text "filter"
  search_ <- Twain.paramMaybe @Text "search"
  runDbOr500 pool (toggleTodoSession i)
  items <- runDbOr500 pool getTodosSession
  -- breakpointM
  render $ todoListSection items (fromMaybe "" search_) (fromMaybe "all" filter_)

deleteTodo :: Pool -> ResponderM a
deleteTodo pool = do
  i <- Twain.param @Int64 "id"
  filter_ <- Twain.paramMaybe @Text "filter"
  search_ <- Twain.paramMaybe @Text "search"
  runDbOr500 pool (deleteTodoSession i)
  items <- runDbOr500 pool getTodosSession
  -- breakpointM
  render $ todoListSection items (fromMaybe "" search_) (fromMaybe "all" filter_)

clearCompleted :: Pool -> ResponderM a
clearCompleted pool = do
  filter_ <- Twain.paramMaybe @Text "filter"
  search_ <- Twain.paramMaybe @Text "search"
  runDbOr500 pool clearCompletedSession
  items <- runDbOr500 pool getTodosSession
  -- breakpointM
  render $ todoListSection items (fromMaybe "" search_) (fromMaybe "all" filter_)

editTodoForm :: Pool -> ResponderM a
editTodoForm pool = do
  i <- Twain.param @Int64 "id"
  mTodo <- runDbOr500 pool (getTodoSession i)
  -- breakpointM
  case mTodo of
    Just todo -> render [hsx|
      <li style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0; border-bottom: 1px solid var(--pico-muted-border-color);"
          id={"todo-item-" <> show todo.id :: Text}>
        <form hx-put={"/todos/" <> show todo.id :: Text} hx-target={"#todo-item-" <> show todo.id :: Text} hx-swap="outerHTML" style="width: 100%; display: flex; margin-bottom: 0;">
          <input type="text" name="title" value={todo.title} required autofocus style="flex: 1; margin-bottom: 0;">
          <button type="submit" class="outline" style="margin-left: 0.5rem; width: auto; padding: 0.25rem 0.5rem; margin-bottom: 0;">Save</button>
        </form>
      </li>
    |]
    Nothing -> send $ Twain.status (toEnum 404) $ Twain.html "Todo not found"

updateTodo :: Pool -> ResponderM a
updateTodo pool = do
  i <- Twain.param @Int64 "id"
  title' <- Twain.param @Text "title"
  runDbOr500 pool (updateTodoTitleSession i title')
  mTodo <- runDbOr500 pool (getTodoSession i)
  -- breakpointM
  case mTodo of
    Just todo -> render $ todoItem todo
    Nothing   -> send $ Twain.status (toEnum 404) $ Twain.html "Todo not found"

addTodoSession :: Text -> Session ()
addTodoSession title' = statement title'
  [resultlessStatement| insert into todos (title) values ($1 :: text) |]

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
    <form hx-post="/todos" hx-include="#todo-list-form" hx-target="#todo-list">
      <fieldset role="group">
        <input id="todo-input" name="title" placeholder="What needs to be done?" required>
        <button type="submit">Add</button>
      </fieldset>
    </form>
    <input type="search" name="search"
           hx-get="/todos/list" hx-trigger="input changed delay:300ms, search"
           hx-target="#todo-list" placeholder="Search todos...">
    <nav>
      <ul>
        <li><a href="#" hx-get="/todos/list?filter=all" hx-target="#todo-list">All</a></li>
        <li><a href="#" hx-get="/todos/list?filter=active" hx-target="#todo-list">Active</a></li>
        <li><a href="#" hx-get="/todos/list?filter=completed" hx-target="#todo-list">Completed</a></li>
      </ul>
    </nav>
    {todoListSection items "" filterBy}
  </article>
|]

todoListSection :: [Todo] -> Text -> Text -> Html ()
todoListSection items searchQ filterBy = [hsx|
  <section id="todo-list">
    <form id="todo-list-form">
      <input type="hidden" name="filter" value={filterBy}>
      <input type="hidden" name="search" value={searchQ}>
      <ul style="list-style: none; padding: 0;">
        {mapM_ todoItem matched}
      </ul>
      <footer style="display: flex; justify-content: space-between; align-items: center;">
        <small>{activeCountText}</small>
        {clearButton}
      </footer>
    </form>
  </section>
|]
  where
    searched
      | T.null searchQ = items
      | otherwise      = filter (\t -> T.toLower searchQ `T.isInfixOf` T.toLower t.title) items
    matched = case filterBy of
      "active"    -> filter (not . (.completed)) searched
      "completed" -> filter (.completed) searched
      _           -> searched
    activeCount = length $ filter (not . (.completed)) searched
    activeCountText :: Text
    activeCountText = show activeCount <> " item" <> (if activeCount == 1 then "" else "s") <> " left"
    completedCount = length $ filter (.completed) searched
    completedCountText :: Text
    completedCountText = show completedCount
    clearButton :: Html ()
    clearButton
      | completedCount > 0 = [hsx|
          <button class="outline" hx-post="/todos/clear" hx-include="#todo-list-form" hx-target="#todo-list">
            Clear completed ({completedCountText})
          </button>
        |]
      | otherwise = mempty

todoItem :: Todo -> Html ()
todoItem todo = [hsx|
  <li style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0; border-bottom: 1px solid var(--pico-muted-border-color);"
      id={"todo-item-" <> show todo.id :: Text}>
    {completed}
    {titleHtml}
    <button class="outline secondary" hx-delete={deletePath} hx-include="#todo-list-form" hx-target="#todo-list" hx-confirm="Delete this todo?"
            style="margin-left: auto; width: auto; padding: 0.25rem 0.5rem; margin-bottom: 0;">
      ✕
    </button>
  </li>
|]
  where
    patchPath  = "/todos/" <> show todo.id :: Text
    deletePath = "/todos/" <> show todo.id :: Text
    editPath   = "/todos/" <> show todo.id <> "/edit" :: Text
    completed :: Html ()
    completed
      | todo.completed = [hsx|<input type="checkbox" checked hx-patch={patchPath} hx-include="#todo-list-form" hx-target="#todo-list" style="margin-bottom: 0;">|]
      | otherwise      = [hsx|<input type="checkbox" hx-patch={patchPath} hx-include="#todo-list-form" hx-target="#todo-list" style="margin-bottom: 0;">|]
    titleHtml :: Html ()
    titleHtml
      | todo.completed = [hsx|<s style="opacity: 0.5;" hx-get={editPath} hx-trigger="dblclick" hx-target={"#todo-item-" <> show todo.id :: Text} hx-swap="outerHTML">{todo.title}</s>|]
      | otherwise      = [hsx|<span hx-get={editPath} hx-trigger="dblclick" hx-target={"#todo-item-" <> show todo.id :: Text} hx-swap="outerHTML">{todo.title}</span>|]
