{-# LANGUAGE BlockArguments        #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DerivingVia           #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GHC2024               #-}
{-# LANGUAGE NoFieldSelectors      #-}
{-# LANGUAGE OverloadedRecordDot   #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE PatternSynonyms       #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE TypeApplications      #-}
module Todo
  ( Todo(..)
  , TodoRoutes
  , todoServer
  , getTodosSession
  , addTodoSession
  , toggleTodoSession
  , clearCompletedSession
  ) where

import Data.Aeson
import Data.Text qualified as T
import Data.Vector qualified as V
import Prelude hiding (Handler, id)

import Database
import Hasql.TH
import Htmx
import Http
import Servant.API
import Servant.Server
import Servant.Server.Generic (AsServer)
import Servant.Server.Internal.Handler (pattern MkHandler)
import Web.FormUrlEncoded

data Todo = Todo { id :: Int64, title :: Text, completed :: Bool }
  deriving (Eq, Show)

instance ToJSON Todo where
  toJSON todo =
    object
      [ "id" .= todo.id
      , "title" .= todo.title
      , "completed" .= todo.completed
      ]

data TodoListState = TodoListState
  { stateFilter :: Maybe Text
  , stateTitle  :: Maybe Text
  } deriving (Eq, Show)

instance FromJSON TodoListState where
  parseJSON = withObject "TodoListState" \obj ->
    TodoListState
      <$> obj .:? "filter"
      <*> obj .:? "title"

instance FromForm TodoListState where
  fromForm form =
    TodoListState
      <$> parseMaybe "filter" form
      <*> parseMaybe "title" form

data AddTodoRequest = AddTodoRequest
  { addTitle :: Text
  , addState :: TodoListState
  } deriving (Eq, Show)

instance FromJSON AddTodoRequest where
  parseJSON = withObject "AddTodoRequest" \obj ->
    AddTodoRequest
      <$> obj .:? "title" .!= ""
      <*> parseJSON (Object obj)

instance FromForm AddTodoRequest where
  fromForm form =
    AddTodoRequest
      <$> parseUnique "title" form
      <*> fromForm form

data UpdateTodoRequest = UpdateTodoRequest
  { updateTitle :: Text
  , updateState :: TodoListState
  } deriving (Eq, Show)

instance FromJSON UpdateTodoRequest where
  parseJSON = withObject "UpdateTodoRequest" \obj -> do
    editTitle <- obj .:? "edit-title"
    title <- obj .:? "title"
    UpdateTodoRequest
      (fromMaybe "" (editTitle <|> title))
      <$> parseJSON (Object obj)

instance FromForm UpdateTodoRequest where
  fromForm form = do
    editTitle <- parseMaybe "edit-title" form
    title <- parseMaybe "title" form
    UpdateTodoRequest
      (fromMaybe "" (editTitle <|> title))
      <$> fromForm form

data TodoMutationStatus
  = TodoCreated
  | TodoDuplicate
  | TodoEmptyTitle
  | TodoToggled
  | TodoDeleted
  | TodoCleared
  | TodoUpdated
  | TodoUpdateDuplicate
  deriving (Eq, Show)

instance ToJSON TodoMutationStatus where
  toJSON = \case
    TodoCreated         -> "created"
    TodoDuplicate       -> "duplicate"
    TodoEmptyTitle      -> "empty-title"
    TodoToggled         -> "toggled"
    TodoDeleted         -> "deleted"
    TodoCleared         -> "cleared"
    TodoUpdated         -> "updated"
    TodoUpdateDuplicate -> "update-duplicate"

data TodosView = TodosView
  { todos       :: [Todo]
  , filterBy    :: Text
  , searchTitle :: Text
  } deriving (Eq, Show)

instance ToJSON TodosView where
  toJSON todosView =
    object
      [ "todos" .= todosView.todos
      , "filter" .= todosView.filterBy
      , "title" .= todosView.searchTitle
      ]

instance MimeRender HTML TodosView where
  mimeRender _ todosView = renderBS $ todoPage todosView.todos todosView.filterBy

data TodoListView = TodoListView
  { todos             :: [Todo]
  , filterBy          :: Text
  , searchTitle       :: Text
  , highlightedTodoId :: Maybe Int64
  , outOfBand         :: Bool
  } deriving (Eq, Show)

instance ToJSON TodoListView where
  toJSON listView =
    object
      [ "todos" .= listView.todos
      , "filter" .= listView.filterBy
      , "title" .= listView.searchTitle
      , "highlightedTodoId" .= listView.highlightedTodoId
      , "outOfBand" .= listView.outOfBand
      ]

instance MimeRender HTML TodoListView where
  mimeRender _ listView =
    renderBS $
      todoListSectionHighlightedOob
        listView.todos
        listView.searchTitle
        listView.filterBy
        listView.highlightedTodoId
        listView.outOfBand

newtype TodoEditView = TodoEditView Todo
  deriving (Eq, Show)

instance ToJSON TodoEditView where
  toJSON (TodoEditView todo) = toJSON todo

instance MimeRender HTML TodoEditView where
  mimeRender _ (TodoEditView todo) = renderBS $ todoEditForm todo

data TodoMutationView = TodoMutationView
  { todos             :: [Todo]
  , filterBy          :: Text
  , searchTitle       :: Text
  , mutation          :: TodoMutationStatus
  , highlightedTodoId :: Maybe Int64
  } deriving (Eq, Show)

instance ToJSON TodoMutationView where
  toJSON mutationResult =
    object
      [ "todos" .= mutationResult.todos
      , "filter" .= mutationResult.filterBy
      , "title" .= mutationResult.searchTitle
      , "mutation" .= mutationResult.mutation
      , "highlightedTodoId" .= mutationResult.highlightedTodoId
      ]

instance MimeRender HTML TodoMutationView where
  mimeRender _ mutationResult = renderBS case mutationResult.mutation of
    TodoCreated    -> addResponseHtml
    TodoDuplicate  -> addResponseHtml
    TodoEmptyTitle -> addResponseHtml
    _              -> todoListHtml
    where
      addResponseHtml = do
        todoAddForm
        todoListSectionHighlightedOob mutationResult.todos "" mutationResult.filterBy mutationResult.highlightedTodoId True
      todoListHtml =
        todoListSection mutationResult.todos mutationResult.searchTitle mutationResult.filterBy

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
      :> ReqBody '[FormUrlEncoded, JSON] AddTodoRequest
      :> Post '[HTML, JSON] TodoMutationView
  , clear
      :: mode :- "todos" :> "clear"
      :> ReqBody '[FormUrlEncoded, JSON] TodoListState
      :> Post '[HTML, JSON] TodoMutationView
  , item
      :: mode :- "todos"
      :> Capture "id" Int64
      :> NamedRoutes TodoItemAPI
  } deriving stock Generic

data TodoItemAPI mode = TodoItemAPI
  { toggle
      :: mode :- ReqBody '[FormUrlEncoded, JSON] TodoListState
      :> Patch '[HTML, JSON] TodoMutationView
  , delete
      :: mode :- ReqBody '[FormUrlEncoded, JSON] TodoListState
      :> Delete '[HTML, JSON] TodoMutationView
  , edit
      :: mode :- "edit"
      :> Get '[HTML, JSON] TodoEditView
  , update
      :: mode :- ReqBody '[FormUrlEncoded, JSON] UpdateTodoRequest
      :> Put '[HTML, JSON] TodoMutationView
  } deriving stock Generic

type TodoRoutes = NamedRoutes TodoAPI

todoAPI :: Proxy TodoRoutes
todoAPI = Proxy

todoServer :: Pool -> TodoAPI AsServer
todoServer pool =
  TodoAPI
    { page = getTodosPage pool
    , list = getTodoListPartial pool
    , add = addTodo pool
    , clear = clearCompleted pool
    , item = todoItemServer pool
    }

todoItemServer :: Pool -> Int64 -> TodoItemAPI AsServer
todoItemServer pool todoId =
  TodoItemAPI
    { toggle = toggleTodo pool todoId
    , delete = deleteTodo pool todoId
    , edit = editTodoForm pool todoId
    , update = updateTodo pool todoId
    }

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

runDbOr500 :: Pool -> Session a -> Handler a
runDbOr500 pool session = do
  res <- liftIO $ runDb pool session
  case res of
    Left err -> throwServerError err500
      { errBody = renderBS [hsx|<div>Database Error: {T.pack (show err)}</div>|]
      }
    Right a -> pure a

getTodosSession :: Session [Todo]
getTodosSession = do
  V.toList . V.map (\(id', title', completed') -> Todo id' title' completed') <$> statement ()
    [vectorStatement|
      select id :: int8, title :: text, completed :: bool from todos order by id
    |]

getTodosPage :: Pool -> Maybe Text -> Maybe Text -> Handler TodosView
getTodosPage pool filter_ search_ = do
  items <- runDbOr500 pool getTodosSession
  pure $ TodosView items (filterText filter_) (searchText search_)

getTodoListPartial :: Pool -> Maybe Text -> Maybe Text -> Handler TodoListView
getTodoListPartial pool filter_ search_ = do
  items   <- runDbOr500 pool getTodosSession
  pure $ TodoListView items (filterText filter_) (searchText search_) Nothing False

addTodo :: Pool -> AddTodoRequest -> Handler TodoMutationView
addTodo pool request = do
  let normalizedTitle = normalizeTitle request.addTitle
  isDuplicate <- runDbOr500 pool (todoTitleExistsSession normalizedTitle)
  duplicateTodo <-
    if isDuplicate
      then runDbOr500 pool (getTodoByTitleSession normalizedTitle)
      else pure Nothing
  unless (T.null normalizedTitle || isDuplicate) $
    runDbOr500 pool (addTodoSession normalizedTitle)
  items <- runDbOr500 pool getTodosSession
  pure TodoMutationView
    { todos = items
    , filterBy = stateFilterText request.addState
    , searchTitle = ""
    , mutation = addMutationStatus normalizedTitle isDuplicate
    , highlightedTodoId = fmap (.id) duplicateTodo
    }

toggleTodo :: Pool -> Int64 -> TodoListState -> Handler TodoMutationView
toggleTodo pool todoId listState = do
  runDbOr500 pool (toggleTodoSession todoId)
  items <- runDbOr500 pool getTodosSession
  pure $ mutationView TodoToggled listState items Nothing

deleteTodo :: Pool -> Int64 -> TodoListState -> Handler TodoMutationView
deleteTodo pool todoId listState = do
  runDbOr500 pool (deleteTodoSession todoId)
  items <- runDbOr500 pool getTodosSession
  pure $ mutationView TodoDeleted listState items Nothing

clearCompleted :: Pool -> TodoListState -> Handler TodoMutationView
clearCompleted pool listState = do
  runDbOr500 pool clearCompletedSession
  items <- runDbOr500 pool getTodosSession
  pure $ mutationView TodoCleared listState items Nothing

editTodoForm :: Pool -> Int64 -> Handler TodoEditView
editTodoForm pool todoId = do
  mTodo <- runDbOr500 pool (getTodoSession todoId)
  case mTodo of
    Just todo -> pure $ TodoEditView todo
    Nothing   -> throwServerError err404 { errBody = "Todo not found" }

updateTodo :: Pool -> Int64 -> UpdateTodoRequest -> Handler TodoMutationView
updateTodo pool todoId request = do
  let title' = request.updateTitle
  let normalizedTitle = normalizeTitle title'
  isDuplicate <- runDbOr500 pool (todoTitleExistsExceptSession todoId normalizedTitle)
  unless (T.null normalizedTitle || isDuplicate) $
    runDbOr500 pool (updateTodoTitleSession todoId normalizedTitle)
  items <- runDbOr500 pool getTodosSession
  pure $ mutationView
    (if isDuplicate then TodoUpdateDuplicate else TodoUpdated)
    request.updateState
    items
    Nothing

filterText :: Maybe Text -> Text
filterText = fromMaybe "all"

searchText :: Maybe Text -> Text
searchText = fromMaybe ""

stateFilterText :: TodoListState -> Text
stateFilterText = filterText . (.stateFilter)

stateSearchText :: TodoListState -> Text
stateSearchText = searchText . (.stateTitle)

addMutationStatus :: Text -> Bool -> TodoMutationStatus
addMutationStatus titleExists isDuplicate
  | T.null titleExists = TodoEmptyTitle
  | isDuplicate = TodoDuplicate
  | otherwise = TodoCreated

mutationView :: TodoMutationStatus -> TodoListState -> [Todo] -> Maybe Int64 -> TodoMutationView
mutationView status listState items highlightedTodoId' =
  TodoMutationView
    { todos = items
    , filterBy = stateFilterText listState
    , searchTitle = stateSearchText listState
    , mutation = status
    , highlightedTodoId = highlightedTodoId'
    }

throwServerError :: Servant.Server.ServerError -> Handler a
throwServerError err = MkHandler $ pure $ Left err

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
todoPage items filterBy = pageShell [hsx|
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

todoEditForm :: Todo -> Html ()
todoEditForm todo = [hsx|
  <li style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0; border-bottom: 1px solid var(--pico-muted-border-color);"
      id={"todo-item-" <> show todo.id :: Text}>
    <form hx-put={"/todos/" <> show todo.id :: Text} hx-include={listStateInclude} hx-target="#todo-list" hx-swap={listSwap} style="width: 100%; display: flex; margin-bottom: 0;">
      <input type="text" name="edit-title" value={todo.title} required autofocus style="flex: 1; margin-bottom: 0;">
      <button type="submit" class="outline" style="margin-left: 0.5rem; width: auto; padding: 0.25rem 0.5rem; margin-bottom: 0;">Save</button>
    </form>
  </li>
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
