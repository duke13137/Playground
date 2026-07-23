{-# LANGUAGE BlockArguments    #-}
{-# LANGUAGE OverloadedStrings #-}

module Database
  ( Pool.Pool
  , module Hasql.Session
  , module Hasql.Statement
  , module Hasql.Errors
  , acquirePool
  , releasePool
  , runDb
  ) where

import Hasql.Connection.Settings qualified as Connection
import Hasql.Errors
import Hasql.Pool qualified as Pool
import Hasql.Pool.Config qualified as Pool
import Hasql.Session
import Hasql.Statement
import Pqi.Native qualified as Pqi

acquirePool :: IO Pool.Pool
acquirePool = do
  setting <- getConnectionSetting
  Pool.acquire
    Pqi.adapter
    ( Pool.settings
        [ Pool.size 8
        , Pool.acquisitionTimeout 10
        , Pool.agingTimeout 1800
        , Pool.idlenessTimeout 1800
        , Pool.staticConnectionSettings setting
        ]
    )

releasePool :: Pool.Pool -> IO ()
releasePool = Pool.release

runDb :: Pool.Pool -> Session a -> IO (Either Pool.UsageError a)
runDb = Pool.use

getConnectionSetting :: IO Connection.Settings
getConnectionSetting = do
  host     <- lookupEnv "PGHOST"
  port     <- lookupEnv "PGPORT"
  dbname   <- lookupEnv "PGDATABASE"
  user     <- lookupEnv "PGUSER"
  password <- lookupEnv "PGPASSWORD"
  return $ mconcat
    [ Connection.hostAndPort (maybe "127.0.0.1" toText host) (fromMaybe 5432 (readMaybe (fromMaybe "" port)))
    , Connection.dbname    (maybe "postgres"  toText dbname)
    , Connection.user      (maybe "postgres"  toText user)
    , Connection.password  (maybe (error "PGPASSWORD not set") toText password)
    ]
