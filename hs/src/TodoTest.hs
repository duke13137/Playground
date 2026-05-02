{-# LANGUAGE BlockArguments        #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DerivingVia           #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GHC2024               #-}
{-# LANGUAGE NoFieldSelectors      #-}
{-# LANGUAGE OverloadedRecordDot   #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
module TodoTest (tasty, testRoute, testDB) where

import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.Char (isDigit)
import Data.List qualified as List
import Data.Text qualified as T
import Database
import Hasql.TH
import Network.HTTP.Types.Header (RequestHeaders)
import Network.HTTP.Types.Method (StdMethod (..))
import Network.Wai
import Network.Wai.Test qualified as WaiTest
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.Wai hiding (Session, head)
import Test.Tasty.Wai qualified as Test

import App (app)
import Todo

tasty :: TestTree -> IO ()
tasty action =
  bracket
    (hGetBuffering stdout)
    (hSetBuffering stdout)
    (const $ defaultMain action)

-- $> tasty testRoute
testRoute :: TestTree
testRoute = withResource acquirePool releasePool \getPool ->
  inOrderTestGroup "Todo web behavior"
  [ testWai (appWithPool getPool) "Hello World" do
      resp <- Test.get "/"
      assertStatus 200 resp
      assertBodyContains "Welcome" resp
  , testWai (appWithPool getPool) "Not found" do
      resp <- Test.get "/notfound"
      assertStatus 404 resp
      assertBodyContains "Not found" resp
  , testWai (appWithPool getPool) "GET /todos" do
      resp <- Test.get "/todos"
      assertStatus 200 resp
      assertBodyContains "Todos" resp
      assertBodyContains "What needs to be done?" resp
      assertBodyContains "hx-get=\"/todos/list\"" resp
      assertBodyContains "hx-trigger=\"input changed delay:500ms\"" resp
      assertBodyContains "hx-include=\"#todo-list-form [name=&#39;filter&#39;], #todo-input\"" resp
      assertBodyContains "hx-sync=\"closest form:abort\"" resp
      assertBodyContains "hx-post=\"/todos\"" resp
      assertBodyDoesNotContain "data-hx-json" resp
      assertBodyDoesNotContain "form-json.js" resp
  , testWai (appWithPool getPool) "JSON clients use the same todo routes" do
      pool <- liftIO getPool
      _ <- liftIO $ runDb pool truncateTodosSession

      respAdd <- postJsonApi "/todos" "{\"title\":\"JSON Task\"}"
      assertStatus 200 respAdd
      assertContentTypePrefix "application/json" respAdd
      assertBodyContains "\"mutation\":\"created\"" respAdd
      assertBodyContains "\"title\":\"JSON Task\"" respAdd

      respPage <- getJson "/todos"
      assertStatus 200 respPage
      assertContentTypePrefix "application/json" respPage
      assertBodyContains "\"todos\"" respPage
      assertBodyContains "\"title\":\"JSON Task\"" respPage
  , testWai (appWithPool getPool) "user can manage todos through htmx routes" do
      pool <- liftIO getPool
      _ <- liftIO $ runDb pool truncateTodosSession

      -- 1. Create
      respAdd <- postForm "/todos" "title=Buy+milk"
      assertStatus 200 respAdd
      assertBodyContains "id=\"add-form\"" respAdd
      assertBodyContains "hx-swap-oob=\"outerMorph\"" respAdd
      assertBodyContains "Buy milk" respAdd
      respList <- Test.get "/todos/list"
      assertStatus 200 respList
      assertBodyContains "Buy milk" respList

      -- Get the inserted task ID from the public HTML representation.
      firstId <- liftIO $ requireFirstTodoId "created todo" respAdd
      let idStr = encodeUtf8 (show firstId :: Text)

      -- 2. Edit Form
      let editPath = "/todos/" <> idStr <> "/edit"
      respEdit <- Test.get editPath
      assertStatus 200 respEdit
      assertBodyContains "Buy milk" respEdit
      assertBodyContains "Save" respEdit

      -- 3. Update
      let updatePath = "/todos/" <> idStr
      respUpdate <- putForm updatePath "edit-title=Buy+water"
      assertStatus 200 respUpdate
      assertBodyContains "Buy water" respUpdate

      -- 4. Delete
      let deletePath = "/todos/" <> idStr
      respDelete <- deleteForm deletePath ""
      assertStatus 200 respDelete

      -- Verify deletion
      respList2 <- Test.get "/todos/list"
      assertStatus 200 respList2
      assertBodyDoesNotContain "Buy water" respList2

      -- 5. Create multiple, toggle, search, clear
      _ <- postForm "/todos" "title=Task+A"
      _ <- postForm "/todos" "title=Task+B"
      _ <- postForm "/todos" "title=Task+C"
      respDupAdd <- postForm "/todos" "title=Task+C"
      assertStatus 200 respDupAdd
      assertBodyContains "todo-highlight" respDupAdd

      -- Search for token prefixes of "Task A"
      respSearch <- Test.get "/todos/list?title=Ta%20A"
      assertStatus 200 respSearch
      assertBodyContains "Task A" respSearch
      assertBodyDoesNotContain "Task B" respSearch

      respTokenPrefixSearch <- Test.get "/todos/list?title=A"
      assertStatus 200 respTokenPrefixSearch
      assertBodyContains "Task A" respTokenPrefixSearch
      assertBodyDoesNotContain "Task B" respTokenPrefixSearch
      assertBodyDoesNotContain "Task C" respTokenPrefixSearch

      -- Get all IDs from the public HTML representation and toggle first two.
      respAll <- Test.get "/todos/list"
      allIds <- liftIO $ requireTodoIds "three created todos" 3 respAll
      case allIds of
        (a:b:_) -> do
          let bStr = encodeUtf8 (show b :: Text)
          respDupUpdate <- putForm ("/todos/" <> bStr) "edit-title=Task+A"
          assertStatus 200 respDupUpdate
          assertBodyContains "Task A" respDupUpdate
          assertBodyContains "Task B" respDupUpdate
          assertBodyContains "Task C" respDupUpdate

          let aStr = encodeUtf8 (show a :: Text)
          _ <- patchForm ("/todos/" <> aStr) ""
          _ <- patchForm ("/todos/" <> bStr) ""
          pass
        _ -> liftIO $ assertFailure "Expected at least 2 todos"

      -- Verify completed/active state through filtered HTTP representations.
      respCompleted <- Test.get "/todos/list?filter=completed"
      assertStatus 200 respCompleted
      assertBodyContains "Task A" respCompleted
      assertBodyContains "Task B" respCompleted
      assertBodyDoesNotContain "Task C" respCompleted

      -- Filter active
      respActive <- Test.get "/todos/list?filter=active"
      assertStatus 200 respActive
      assertBodyContains "Task C" respActive
      assertBodyDoesNotContain "Task A" respActive
      assertBodyDoesNotContain "Task B" respActive

      -- Clear completed
      respClear <- postForm "/todos/clear" ""
      assertStatus 200 respClear

      -- Verify only the incomplete item remains through the public route.
      respRemaining <- Test.get "/todos/list"
      assertStatus 200 respRemaining
      assertBodyContains "Task C" respRemaining
      assertBodyDoesNotContain "Task A" respRemaining
      assertBodyDoesNotContain "Task B" respRemaining
  ]

appWithPool :: IO Pool -> Application
appWithPool getPool req respond = do
  pool <- getPool
  app pool req respond

jsonHtmlHeaders :: RequestHeaders
jsonHtmlHeaders =
  [ ("Content-Type", "application/json")
  , ("Accept", "text/html")
  ]

jsonApiHeaders :: RequestHeaders
jsonApiHeaders =
  [ ("Content-Type", "application/json")
  , ("Accept", "application/json")
  ]

acceptJsonHeaders :: RequestHeaders
acceptJsonHeaders =
  [ ("Accept", "application/json")
  ]

formHtmlHeaders :: RequestHeaders
formHtmlHeaders =
  [ ("Content-Type", "application/x-www-form-urlencoded")
  , ("Accept", "text/html")
  ]

postJson :: ByteString -> LBS.ByteString -> Test.Session WaiTest.SResponse
postJson path body =
  Test.postWithHeaders path body jsonHtmlHeaders

postJsonApi :: ByteString -> LBS.ByteString -> Test.Session WaiTest.SResponse
postJsonApi path body =
  Test.postWithHeaders path body jsonApiHeaders

putJson :: ByteString -> LBS.ByteString -> Test.Session WaiTest.SResponse
putJson path body =
  Test.srequest $ Test.buildRequestWithHeaders PUT path body jsonHtmlHeaders

patchJson :: ByteString -> LBS.ByteString -> Test.Session WaiTest.SResponse
patchJson path body =
  Test.srequest $ Test.buildRequestWithHeaders PATCH path body jsonHtmlHeaders

deleteJson :: ByteString -> LBS.ByteString -> Test.Session WaiTest.SResponse
deleteJson path body =
  Test.srequest $ Test.buildRequestWithHeaders DELETE path body jsonHtmlHeaders

postForm :: ByteString -> LBS.ByteString -> Test.Session WaiTest.SResponse
postForm path body =
  Test.postWithHeaders path body formHtmlHeaders

putForm :: ByteString -> LBS.ByteString -> Test.Session WaiTest.SResponse
putForm path body =
  Test.srequest $ Test.buildRequestWithHeaders PUT path body formHtmlHeaders

patchForm :: ByteString -> LBS.ByteString -> Test.Session WaiTest.SResponse
patchForm path body =
  Test.srequest $ Test.buildRequestWithHeaders PATCH path body formHtmlHeaders

deleteForm :: ByteString -> LBS.ByteString -> Test.Session WaiTest.SResponse
deleteForm path body =
  Test.srequest $ Test.buildRequestWithHeaders DELETE path body formHtmlHeaders

getJson :: ByteString -> Test.Session WaiTest.SResponse
getJson path =
  Test.srequest $ Test.buildRequestWithHeaders GET path "" acceptJsonHeaders

assertContentTypePrefix :: ByteString -> WaiTest.SResponse -> Test.Session ()
assertContentTypePrefix expected response =
  liftIO $
    case List.lookup "Content-Type" (WaiTest.simpleHeaders response) of
      Just contentType ->
        assertBool
          ("expected Content-Type prefix " <> show expected <> ", got " <> show contentType)
          (expected `BS.isPrefixOf` contentType)
      Nothing -> assertFailure "response did not include Content-Type"

responseBodyText :: WaiTest.SResponse -> Text
responseBodyText =
  decodeUtf8 . WaiTest.simpleBody

assertBodyDoesNotContain :: Text -> WaiTest.SResponse -> Test.Session ()
assertBodyDoesNotContain needle response =
  liftIO $
    assertBool
      ("response body should not contain " <> toString needle)
      (not (needle `T.isInfixOf` responseBodyText response))

requireFirstTodoId :: String -> WaiTest.SResponse -> IO Int64
requireFirstTodoId label response =
  case todoIdsFromResponse response of
    todoId:_ -> pure todoId
    []       -> assertFailure $ "Expected todo id in response for " <> label

requireTodoIds :: String -> Int -> WaiTest.SResponse -> IO [Int64]
requireTodoIds label expectedCount response = do
  let todoIds = todoIdsFromResponse response
  if length todoIds >= expectedCount
    then pure todoIds
    else assertFailure $
      "Expected at least "
        <> show expectedCount
        <> " todo ids in response for "
        <> label
        <> ", found "
        <> show (length todoIds)

todoIdsFromResponse :: WaiTest.SResponse -> [Int64]
todoIdsFromResponse =
  todoIdsFromText . responseBodyText

todoIdsFromText :: Text -> [Int64]
todoIdsFromText body =
  case T.breakOn todoItemIdPrefix body of
    (_, rest)
      | T.null rest -> []
      | otherwise ->
          let afterPrefix = T.drop (T.length todoItemIdPrefix) rest
              (digits, remaining) = T.span isDigit afterPrefix
           in maybe id (:) (readMaybe (toString digits)) (todoIdsFromText remaining)
  where
    todoItemIdPrefix = "id=\"todo-item-"

truncateTodosSession :: Session ()
truncateTodosSession =
  statement ()
    [resultlessStatement|
      delete from todos
    |]

-- $> tasty testDB
testDB :: TestTree
testDB = withResource acquirePool releasePool $ \getPool ->
  testGroup "Todo persistence behavior"
    [ testCase "Todo CRUD" do
        pool <- getPool
        -- clear before test
        _ <- runDb pool truncateTodosSession

        -- Insert
        _ <- runDb pool (addTodoSession "Test Task 1")
        _ <- runDb pool (addTodoSession "Test Task 2")

        -- Verify Insert
        todos1 <- runDb pool getTodosSession
        case todos1 of
          Right ts -> do
             length ts @?= 2
             case ts of
                (firstTodo:_) -> firstTodo.title @?= "Test Task 1"
                _             -> assertFailure "Expected list with elements"
          Left err -> assertFailure $ "DB Error: " ++ show err

        -- Complete a task
        let todos1' = fromRight [] todos1
        case todos1' of
            (firstTodo:_) -> do
                _ <- runDb pool (toggleTodoSession firstTodo.id)

                todos2 <- runDb pool getTodosSession
                case todos2 of
                    Right ts2 -> case ts2 of
                        (t2:_) -> t2.completed @?= True
                        _      -> assertFailure "Expected list"
                    Left err -> assertFailure $ "DB Error: " ++ show err
            _ -> pass

        -- Clear completed
        _ <- runDb pool clearCompletedSession

        todos3 <- runDb pool getTodosSession
        case todos3 of
          Right ts -> length ts @?= 1
          Left err -> assertFailure $ "DB Error: " ++ show err
    ]
