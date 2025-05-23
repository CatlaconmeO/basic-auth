import { Elysia } from 'elysia'
import { auth } from './routes/auth'

const app = new Elysia()
  .use(auth)

app.listen(3000)

console.log("🦊 Elysia is running at http://localhost:3000")
