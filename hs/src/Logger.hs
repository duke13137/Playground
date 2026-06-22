{-# LANGUAGE BlockArguments    #-}
{-# LANGUAGE GHC2024           #-}
{-# LANGUAGE OverloadedStrings #-}

module Logger
  ( logDebug
  , logInfo
  , logError
  , closeLogger
  ) where

import Colog.Core.Action (LogAction (..), cmap)
import Colog.Message qualified as Colog
import Colog.Monad (LoggerT, usingLoggerT)
import Control.Monad.IO.Class (MonadIO (liftIO))
import Data.Text (Text)
import GHC.Stack (HasCallStack, withFrozenCallStack)
import System.IO.Unsafe (unsafePerformIO)
import System.Log.FastLogger (FastLogger, LogStr, LogType' (LogStdout), defaultBufSize, newFastLogger, toLogStr)

fastLogger :: (FastLogger, IO ())
fastLogger = unsafePerformIO $ newFastLogger (LogStdout defaultBufSize)
{-# NOINLINE fastLogger #-}

loggerAction :: MonadIO m => FastLogger -> LogAction m LogStr
loggerAction logger' = LogAction $ \logStr -> liftIO $ logger' logStr

fmtLogStr :: Colog.Message -> LogStr
fmtLogStr = toLogStr . (<> "\n") . Colog.fmtMessage

runLogger :: MonadIO m => LoggerT Colog.Message m a -> m a
runLogger = usingLoggerT $ cmap fmtLogStr (loggerAction (fst fastLogger))

closeLogger :: IO ()
closeLogger = snd fastLogger

logDebug :: (HasCallStack, MonadIO m) => Text -> m ()
logDebug msg = withFrozenCallStack $ runLogger $ Colog.logDebug msg

logInfo :: (HasCallStack, MonadIO m) => Text -> m ()
logInfo msg =  withFrozenCallStack $ runLogger $ Colog.logInfo msg

logError :: (HasCallStack, MonadIO m) => Text -> m ()
logError msg = withFrozenCallStack $ runLogger $ Colog.logError msg
