{-# LANGUAGE BlockArguments        #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DerivingVia           #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GHC2024               #-}
{-# LANGUAGE NoFieldSelectors      #-}
{-# LANGUAGE OverloadedRecordDot   #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
module App.TodoTest (tasty, testRoute, testDB) where

import Data.ByteString qualified as BS
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
import Test.Tasty.Ingredients (composeReporters)
import Test.Tasty.Ingredients.ConsoleReporter (consoleTestReporter)
import Test.Tasty.Runners.Html (HtmlPath (HtmlPath), htmlRunner)
import Test.Tasty.Wai hiding (Session, head)
import Test.Tasty.Wai qualified as Test

import App (app, appWithTodoGenerator)

import App.Todo

tasty :: TestTree -> IO ()
tasty action =
  bracket
    (hGetBuffering stdout)
    (hSetBuffering stdout)
    (const $ defaultMainWithIngredients ingredients tests)
  where
    ingredients =
      htmlRunner `composeReporters` consoleTestReporter : defaultIngredients
    tests = localOption (Just (HtmlPath "tasty.html")) action

--- $> tasty testDB
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

-- $> tasty testRoute
testRoute :: TestTree
testRoute = withResource acquirePool releasePool \getPool ->
  inOrderTestGroup "Todo web behavior"
  [ testWai (appWithPool getPool) "Home page" do
      resp <- Test.get "/"
      assertStatus 200 resp
      assertBodyContains "Welcome" resp
  , testWai (appWithPool getPool) "Not found" do
      resp <- Test.get "/notfound"
      assertStatus 404 resp
      assertBodyContains "Not found" resp
  , testWai (appWithPool getPool) "Method mismatch returns 405" do
      resp <- Test.srequest $ Test.buildRequestWithHeaders POST "/" "" []
      assertStatus 405 resp
  , testWai (appWithPool getPool) "GET /todos" do
      resp <- Test.get "/todos"
      assertStatus 200 resp
      assertBodyContains "<section class=\"todoapp\">" resp
      assertBodyContains "<h1>todos</h1>" resp
      assertBodyContains "What needs to be done?" resp
      assertBodyContains "class=\"new-todo\"" resp
      assertBodyContains "hx-get=\"/todos/list\"" resp
      assertBodyContains "hx-trigger=\"input changed delay:500ms\"" resp
      assertBodyContains "hx-include=\"#todo-list-form input[name=&#39;filter&#39;]\"" resp
      assertBodyContains "hx-swap=\"outerMorph\"" resp
      assertBodyContains "hx-sync=\"closest form:abort\"" resp
      assertBodyContains "hx-post=\"/todos\"" resp
      assertBodyContains "class=\"todo-list\"" resp
      assertBodyContains "Double-click to edit, Enter to add" resp
      assertBodyContains "I feel lucky today" resp
      assertBodyContains "hx-post=\"/todos/generate\"" resp
      assertBodyContains "type=\"button\"" resp
  , testWai (appWithPoolAndGenerator getPool (const (pure (Right ["Buy milk", "Write plan", "Pack lunch"])))) "POST /todos/generate inserts generated titles" do
      pool <- liftIO getPool
      _ <- liftIO $ runDb pool truncateTodosSession
      resp <- postForm "/todos/generate" "title=Plan+my+morning"
      assertStatus 200 resp
      assertBodyContains "id=\"add-form\"" resp
      assertBodyContains "I feel lucky today" resp
      assertBodyContains "hx-swap-oob=\"outerMorph\"" resp
      assertBodyContains "Buy milk" resp
      assertBodyContains "Write plan" resp
      assertBodyContains "Pack lunch" resp
      respList <- Test.get "/todos/list"
      assertStatus 200 respList
      assertBodyContains "Buy milk" respList
      assertBodyContains "Write plan" respList
      assertBodyContains "Pack lunch" respList
  , testWai (appWithPoolAndGenerator getPool (const (pure (Right ["Task A", "", "task a", "Task B"])))) "POST /todos/generate filters duplicates and empty" do
      pool <- liftIO getPool
      _ <- liftIO $ runDb pool truncateTodosSession
      _ <- postForm "/todos" "title=Task+A"
      respGen <- postForm "/todos/generate" "title=Generate+tasks"
      assertStatus 200 respGen
      respList <- Test.get "/todos/list"
      _todoIds <- liftIO $ requireTodoIds "generated duplicate filtering" 2 respList
      assertBodyContains "Task A" respList
      assertBodyContains "Task B" respList
  , testWai (appWithPoolAndGenerator getPool (const (pure (Left "boom")))) "POST /todos/generate failure renders inline message" do
      pool <- liftIO getPool
      _ <- liftIO $ runDb pool truncateTodosSession
      resp <- postForm "/todos/generate" "title=test"
      assertStatus 200 resp
      assertBodyContains "Could not generate todos; check DEEPSEEK_API_KEY and try again." resp
      assertBodyContains "I feel lucky today" resp
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
      assertBodyContains "class=\"editing\"" respEdit
      assertBodyContains "class=\"edit\"" respEdit

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
      assertBodyContains "duplicate-flash" respDupAdd

      -- Search matches the Clojure app's case-insensitive substring behavior.
      respSearch <- Test.get "/todos/list?title=ask%20A"
      assertStatus 200 respSearch
      assertBodyContains "Task A" respSearch
      assertBodyDoesNotContain "Task B" respSearch

      respNonSubstringSearch <- Test.get "/todos/list?title=Ta%20A"
      assertStatus 200 respNonSubstringSearch
      assertBodyDoesNotContain "Task A" respNonSubstringSearch

      -- Get all IDs from the public HTML representation and toggle first two.
      respAll <- Test.get "/todos/list"
      allIds <- liftIO $ requireTodoIds "three created todos" 3 respAll
      case allIds of
        (a:b:_) -> do
          let bText = show b :: Text
          let bStr = encodeUtf8 bText
          respDupUpdate <- putForm ("/todos/" <> bStr) "edit-title=Task+A"
          assertStatus 200 respDupUpdate
          assertBodyContains "Task A" respDupUpdate
          assertBodyContains "Task C" respDupUpdate
          assertBodyContains "duplicate-flash" respDupUpdate
          assertBodyContains "class=\"editing\"" respDupUpdate
          assertBodyContains "value=\"Task A\"" respDupUpdate
          assertBodyContains (fromStrict $ encodeUtf8 (".querySelector('#todo-" <> bText <> " .edit')?.focus()" :: Text)) respDupUpdate

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

appWithPoolAndGenerator :: IO Pool -> GenerateTodoTitles -> Request -> (Response -> IO ResponseReceived) -> IO ResponseReceived
appWithPoolAndGenerator getPool generate req respond = do
  pool <- getPool
  appWithTodoGenerator generate pool req respond

formHtmlHeaders :: RequestHeaders
formHtmlHeaders =
  [ ("Content-Type", "application/x-www-form-urlencoded")
  , ("Accept", "text/html")
  ]

postForm :: ByteString -> LByteString -> Test.Session WaiTest.SResponse
postForm path body =
  Test.postWithHeaders path body formHtmlHeaders

putForm :: ByteString -> LByteString -> Test.Session WaiTest.SResponse
putForm path body =
  Test.srequest $ Test.buildRequestWithHeaders PUT path body formHtmlHeaders

patchForm :: ByteString -> LByteString -> Test.Session WaiTest.SResponse
patchForm path body =
  Test.srequest $ Test.buildRequestWithHeaders PATCH path body formHtmlHeaders

deleteForm :: ByteString -> LByteString -> Test.Session WaiTest.SResponse
deleteForm path body =
  Test.srequest $ Test.buildRequestWithHeaders DELETE path body formHtmlHeaders

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
    todoItemIdPrefix = "id=\"todo-"

truncateTodosSession :: Session ()
truncateTodosSession =
  statement ()
    [resultlessStatement|
      delete from todos
    |]
