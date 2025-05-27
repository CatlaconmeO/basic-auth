import { Elysia } from 'elysia'
import { auth } from './routes/auth'
import { swagger } from '@elysiajs/swagger'

const app = new Elysia()
  .use(auth)
  .use(swagger())

app.listen(3000)

console.log("🦊 Elysia is running at http://localhost:3000")
