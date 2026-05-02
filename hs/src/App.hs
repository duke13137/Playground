{-# LANGUAGE BlockArguments      #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE GHC2024             #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE PatternSynonyms     #-}
{-# LANGUAGE QuasiQuotes         #-}
{-# LANGUAGE TypeApplications    #-}

module App
  ( app
  , appRoutes
  , logRequest
  , index
  , page404
  ) where

import Prelude hiding (Handler)

import Colog
import Database
import Htmx
import Http
import Network.Wai (Application, Middleware, rawPathInfo, requestMethod)
import Servant.API
import Servant.Server
import Servant.Server.Internal.Handler (pattern MkHandler)

import Todo

type HelloAPI = "hello" :> Capture "name" Text :> Get '[HTML] (Html ())

type AppRoutes =
       Get '[HTML] (Html ())
  :<|> "htmx" :> HelloAPI
  :<|> TodoRoutes
  :<|> CaptureAll "notFound" Text :> Get '[HTML] (Html ())

appRoutes :: Proxy AppRoutes
appRoutes = Proxy

helloHandler :: Pool -> Text -> Handler (Html ())
helloHandler _pool name = pure [hsx|<h1 id="hello">Hello, {name}!</h1>|]

app :: Pool -> Application
app pool =
  logRequest $
    serve appRoutes $
      index
        :<|> helloHandler pool
        :<|> todoServer pool
        :<|> notFound

logger :: MonadIO m => LoggerT Message m a -> m a
logger = usingLoggerT $ cmap fmtMessage logTextStdout

logRequest :: Middleware
logRequest nextApp req sendResponse = do
  let method = requestMethod req
  let path = rawPathInfo req
  logger $ logInfo $ "REQ " <> decodeUtf8 method <> " " <> decodeUtf8 path
  nextApp req sendResponse

index :: Handler (Html ())
index = pure [hsx|<h1>Welcome!</h1>|]

page404 :: Html ()
page404 = [hsx|<h1>Not found...</h1>|]

notFound :: [Text] -> Handler (Html ())
notFound _segments =
  MkHandler $ pure $ Left err404 { errBody = renderBS page404 }
