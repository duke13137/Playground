{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Htmx
  ( hsx
  , pageShell
  , module Lucid
  ) where

import Htmx.QQ (hsx)
import Lucid

pageShell :: Html () -> Html () -> Html ()
pageShell customHead body = [hsx|
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8">
      <script defer src="https://cdn.jsdelivr.net/npm/htmx.org@next/dist/htmax.min.js"></script>
      <script src="https://cdn.jsdelivr.net/npm/scittle@0.8.32/dist/scittle.js" type="application/javascript"></script>
      <script src="https://raw.githubusercontent.com/borkdude/reagami/refs/heads/main/src/reagami/core.cljc" type="application/x-scittle"></script>
      {customHead}
    </head>
    <body>
      {body}
    </body>
  </html>
|]
