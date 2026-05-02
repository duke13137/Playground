{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}

module Http
  ( HTML
  , pageShell
  ) where

import Htmx
import Network.HTTP.Media ((//), (/:))
import Servant.API

data HTML

instance Accept HTML where
  contentType _ = "text" // "html" /: ("charset", "utf-8")

instance MimeRender HTML (Html ()) where
  mimeRender _ = renderBS

pageShell :: Html () -> Html ()
pageShell body = [hsx|
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
      <script src="https://cdn.jsdelivr.net/npm/htmx.org@4.0.0-beta2/dist/htmx.min.js"></script>
    </head>
    <body>
      <main class="container">
      {body}
      </main>
    </body>
  </html>
|]
