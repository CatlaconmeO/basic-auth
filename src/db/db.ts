import { Pool } from 'pg'
import { config } from 'dotenv'
config() 

export const pool = new Pool({ // Sử dụng export để cho phép sử dụng pool ở file khác
  connectionString: process.env.DATABASE_URL,
})