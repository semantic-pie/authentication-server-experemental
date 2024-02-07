import ClientOAuth2 from "client-oauth2"
import cookieParser from "cookie-parser"
import express from "express"
import http from "http"
import path from "path"

const config = {
  clientId: "kek-admin-client",
  clientSecret: "MY SECRET",
  accessTokenUri: "http://localhost:9000/oauth2/token",
  authorizationUri: "http://localhost:9000/oauth2/authorize",
  redirectUri: "http://localhost:3000/oauth2/callback",
  scopes: ["first", "second"],
}

const app = express()
const httpServer = http.createServer(app)

app.use(cookieParser())

const oauth2 = new ClientOAuth2(config)

app.get("/auth", (req, res) => {
  console.log(config)
  const url = oauth2.code.getUri()
  console.log()
  res.redirect(url)
})

app.get("/oauth2/callback", (req, res) =>
  oauth2.code.getToken(req.originalUrl).then(function (user) {
    console.log(user) //=> { accessToken: '...', tokenType: 'bearer', ... }

    // Refresh the current users access token.
    user.refresh().then(function (updatedUser) {
      console.log(updatedUser !== user) //=> true
      console.log(updatedUser.accessToken)
    })

    res.cookie("accessToken", user.accessToken)
    res.redirect("/")
  })
)

// just to watch
app.get("/oauth/config", (req, res) => res.send(config))

app.get("/", (req, res) =>
  res.sendFile("index.html", {
    root: path.resolve(path.dirname("")),
  })
)

httpServer.listen(3000)
