{-# LANGUAGE BlockArguments      #-}
{-# LANGUAGE GHC2024             #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE QuasiQuotes         #-}
{-# LANGUAGE TemplateHaskell     #-}

module App
  ( app
  , appWithTodoGenerator
  ) where

import App.Todo
import Data.ByteString.Lazy qualified as LBS
import Database
import Htmx
import Http
import IHP.Router.WAI (HasPath (..), UrlCapture (..), routeTrieMiddleware, routes)
import Network.HTTP.Types (StdMethod (..), status200, status404)
import Network.Wai (Application, Request, Response, ResponseReceived)
import Prelude hiding (id)
import Web.FormUrlEncoded (FromForm)

data AppRoute
  = HomeAction
  | TodosPageAction { todoFilter :: Maybe Text, title :: Maybe Text }
  | TodoListAction { todoFilter :: Maybe Text, title :: Maybe Text }
  | AddTodoAction
  | ClearTodosAction
  | ToggleTodoAction { todoId :: Integer }
  | DeleteTodoAction { todoId :: Integer, todoFilter :: Maybe Text }
  | EditTodoAction { todoId :: Integer }
  | UpdateTodoAction { todoId :: Integer }
  | GenerateTodosAction
  deriving (Eq, Show)

$(pure [])
[routes|AppRoute
GET /                         HomeAction
GET /todos?filter&title       TodosPageAction { todoFilter = #filter, title = #title }
GET /todos/list?filter&title  TodoListAction { todoFilter = #filter, title = #title }
POST /todos                   AddTodoAction
POST /todos/clear             ClearTodosAction
PATCH /todos/{id}             ToggleTodoAction { todoId = #id }
DELETE /todos/{id}?filter     DeleteTodoAction { todoId = #id, todoFilter = #filter }
GET /todos/{id}/edit          EditTodoAction { todoId = #id }
PUT /todos/{id}               UpdateTodoAction { todoId = #id }
POST /todos/generate          GenerateTodosAction
|]

app :: Pool -> Application
app = appWithTodoGenerator graceGenerateTodoTitles

appWithTodoGenerator :: GenerateTodoTitles -> Pool -> Application
appWithTodoGenerator generate pool = routeTrieMiddleware (appRouteTrie (dispatch generate pool)) notFoundApplication

dispatch :: GenerateTodoTitles -> Pool -> AppRoute -> Application
dispatch _generate _pool HomeAction _req respond =
  respond $ htmlResponse status200 $ renderBS index
dispatch _generate pool (TodosPageAction f t) req respond =
  runView renderTodosViewHtml (getTodosPage pool f t) req respond
dispatch _generate pool (TodoListAction f t) req respond =
  runView renderTodoListViewHtml (getTodoListPartial pool f t) req respond
dispatch _generate pool AddTodoAction req respond =
  withParsedBody req (addTodo pool) renderTodoMutationViewHtml respond
dispatch _generate pool ClearTodosAction req respond =
  withParsedBody req (clearCompleted pool) renderTodoMutationViewHtml respond
dispatch _generate pool (ToggleTodoAction rawId) req respond =
  case routeTodoIdOr404 rawId of
    Left response -> respond response
    Right todoId  -> withParsedBody req (toggleTodo pool todoId) renderTodoMutationViewHtml respond
dispatch _generate pool (DeleteTodoAction rawId f) _req respond =
  case routeTodoIdOr404 rawId of
    Left response -> respond response
    Right todoId  -> runView renderTodoMutationViewHtml (deleteTodo pool todoId f) _req respond
dispatch _generate pool (EditTodoAction rawId) _req respond =
  case routeTodoIdOr404 rawId of
    Left response -> respond response
    Right todoId  -> runView renderTodoEditViewHtml (editTodoForm pool todoId) _req respond
dispatch _generate pool (UpdateTodoAction rawId) req respond =
  case routeTodoIdOr404 rawId of
    Left response -> respond response
    Right todoId  -> withParsedBody req (updateTodo pool todoId) renderTodoMutationViewHtml respond
dispatch generate pool GenerateTodosAction req respond =
  withParsedBody req (generateTodos pool generate) renderTodoMutationViewHtml respond

routeTodoIdOr404 :: Integer -> Either Response Int64
routeTodoIdOr404 rawId =
  case checkedInt64 rawId of
    Nothing     -> Left $ htmlResponse status404 $ renderBS page404
    Just todoId -> Right todoId

runView :: (a -> LBS.ByteString) -> RouteHandler a -> Application
runView renderHtml action req respond = do
  result <- runRouteHandler action
  respond case result of
    Left err    -> errorResponse err
    Right value -> viewResponse renderHtml value

withParsedBody :: FromForm a => Request -> (a -> RouteHandler b) -> (b -> LBS.ByteString) -> (Response -> IO ResponseReceived) -> IO ResponseReceived
withParsedBody req action renderHtml respond = do
  parsed <- runRouteHandler (parseRequestBody req)
  case parsed of
    Left err    -> respond (errorResponse err)
    Right value -> runView renderHtml (action value) req respond

index :: Html ()
index = [hsx|<h1>Welcome!</h1>|]

page404 :: Html ()
page404 = [hsx|<h1>Not found...</h1>|]

notFoundApplication :: Application
notFoundApplication _req respond =
  respond $ htmlResponse status404 $ renderBS page404
