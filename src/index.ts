import { Elysia } from 'elysia'
import { auth } from './routes/auth'
import { swagger } from '@elysiajs/swagger'

const port = process.env.PORT ? Number(process.env.PORT) : 3000;

const app = new Elysia()
  .use(auth)
  .use(swagger())

app.listen(port)

console.log("🦊 Elysia is running at http://localhost:${port}")
