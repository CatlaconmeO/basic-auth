import { Elysia, t } from 'elysia';
import bcryptjs from 'bcryptjs';
import { pool } from '../db/db.js';
import nodemailer from 'nodemailer';
import jwt from 'jsonwebtoken';
import { config } from 'dotenv';
config()

export const auth = new Elysia({ prefix: '/auth' })
    .post('/register',
        async ({ body, set }) => { //Context cần dùng
            const { name, email, password } = body;

            // Kiểm tra xem email đã tồn tại trong DB chưa
            const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
            if (existing.rows.length > 0) {
                set.status = 400;
                return { message: 'Email đã tồn tại' };
            }

            const hashedPassword = await bcryptjs.hash(password, 10);

            //Tạo token xác thực
            const verifyToken = jwt.sign({ name }, process.env.JWT_SECRET as string, { expiresIn: '10s' });

            //Lưu thông tin user vào DB
            const saveUser = await pool.query(
                'INSERT INTO users (name, email, password, verification_token) VALUES ($1, $2, $3, $4) RETURNING *',
                [name, email, hashedPassword, verifyToken]
            )

            // Tạo link xác thực
            const verifyLink = `http://localhost:3000/auth/verify?token=${verifyToken}`;

            // Gửi email xác thực
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.GMAIL_USER,
                    pass: process.env.GMAIL_PASS,
                },
            });

            // Nội email
            const mailOptions = {
                from: process.env.GMAIL_USER,
                to: email,
                subject: 'Xác thực tài khoản',
                text: 'Vui lòng nhấp vào liên kết sau để xác thực tài khoản của bạn: ' + verifyLink,
            };

            //Gửi email
            try {
                await transporter.sendMail(mailOptions);
                set.status = 200;
                return { message: 'Đăng ký thành công, hãy kiểm tra email để xác thực tài khoản' };
            } catch (error) {
                set.status = 500;
                return { message: 'Gửi email thất bại', error };
            }

        },

        {
            body: t.Object({
                name: t.String({
                    minLength: 8,
                    maxLength: 50,
                    error: 'Tên không hợp lệ'
                }),
                email: t.String({
                    format: 'email',
                    error: 'Email không hợp lệ'
                }
                ),
                password: t.String({
                    minLength: 6,
                    error: 'Mật khẩu phải chứa ít nhất 6 ký tự'
                }
                )
            }),
        }
    )


    .get('/verify', async ({ query }) => {
        const { token } = query;

        const user = await pool.query('SELECT * FROM users WHERE verification_token = $1', [token]);

        await pool.query('UPDATE users SET is_verified = true WHERE verification_token = $1', [token]);

        return { message: 'Xác thực thành công' }
    }

    )

    .post('/login',
        async ({ body, set }) => {
            const { email, password } = body;

            // Kiểm tra xem email
            const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email])
            if (existing.rows.length == 0) {
                set.status = 400;
                return { message: 'Email không tồn tại' }
            }

            // Kiểm tra password
            const user = existing.rows[0];
            const isMatch = await bcryptjs.compare(password, user.password);
            if (!isMatch) {
                set.status = 400;
                return { message: 'Mật khẩu không đúng' }
            }

            // Kiểm tra tài khoản đã được xác thực chưa
            const isVerified = user.is_verified;
            if (!isVerified) {
                set.status = 400;
                return { message: 'Tài khoản chưa được xác thực' }
            }

            // Tạo access token và refresh token
            const accessToken = jwt.sign({ id: user.id }, process.env.ACCESS_SECRET as string, { expiresIn: '15m' });
            const refreshToken = jwt.sign({ id: user.id }, process.env.ACCESS_SECRET as string, { expiresIn: '7d' });

            // Lưu refresh token vào DB
            const saveRefreshToken = await pool.query(
                'INSERT INTO refresh_tokens (user_id, token) VALUES ($1, $2) RETURNING *',
                [user.id, refreshToken]
            )

            set.status = 200;
            return {
                message: 'Đăng nhập thành công',
                user: {
                    id: user.id,
                    name: user.name
                },
                accessToken,
                refreshToken
            }
        },
        {
            body: t.Object({
                email: t.String({
                    format: 'email',
                    error: 'Email không hợp lệ'
                }
                ),
                password: t.String({
                    minLength: 6,
                    error: 'Mật khẩu phải chứa ít nhất 6 ký tự'
                }
                )
            }),
        }
    )

    .post('/refresh-token',
        async ({ body, set }) => {
            const { refreshToken } = body;

            // Kiểm tra xem refresh token có hợp lệ không
            const user = await pool.query('SELECT * FROM refresh_tokens WHERE token = $1', [refreshToken]);
            if (user.rows.length == 0) {
                set.status = 400;
                return { message: 'Refresh token không hợp lệ' }
            }
            const userId = user.rows[0].id;

            // Tạo access token mới
            const accessToken = jwt.sign({ id: userId }, process.env.JWT_SECRET as string, { expiresIn: '15m' });

            // Trả về access token mới
            set.status = 200;
            return {
                message: 'Cấp lại access token thành công',
                accessToken
            }
        },
        {
            body: t.Object({
                refreshToken: t.String()
            })
        }
    )

    // Route kiểm tra access token
    .get('/me', async ({ request, set }) => {

    })

