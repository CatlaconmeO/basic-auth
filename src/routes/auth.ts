import { Elysia, t } from 'elysia';
import bcryptjs from 'bcryptjs';
import { pool } from '../db/db.js';
import nodemailer from 'nodemailer';
import jwt from 'jsonwebtoken';
import { sendMails } from '../utils/sendMail.ts';
import axios from 'axios';
import qs from 'qs';
import { config } from 'dotenv';
config()

export const auth = new Elysia({ prefix: '/auth' })
    .post('/register',
        async ({ body, set }) => {
            const { name, email, password } = body;

            // Kiểm tra xem email đã tồn tại trong DB chưa
            const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
            if (existing.rows.length > 0) {
                set.status = 400;
                return { status: 400, message: 'Email đã tồn tại', user: { id: null, name: '', email: '' } };
            }

            const hashedPassword = await bcryptjs.hash(password, 10);

            //Tạo token xác thực
            const verifyToken = jwt.sign({ name }, process.env.JWT_SECRET as string, { expiresIn: '10m' });

            //Lưu thông tin user vào DB
            const saveUser = await pool.query(
                'INSERT INTO users (name, email, password, verification_token) VALUES ($1, $2, $3, $4) RETURNING *',
                [name, email, hashedPassword, verifyToken]
            )

            // Tạo link xác thực
            const verifyLink = `http://localhost:3000/auth/verify?token=${verifyToken}`;

            // Gửi email xác thực
            await sendMails(email, verifyLink);
            set.status = 200;
            return {
                status: 200,
                message: 'Hãy kiểm tra email để xác thực tài khoản, link xác thực sẽ có hiệu lực trong 10 phút',
                user: {
                    id: saveUser.rows[0].id,
                    name: saveUser.rows[0].name,
                    email: saveUser.rows[0].email
                }
            };
        },
        {
            body: t.Object({
                name: t.String({
                    minLength: 6,
                    maxLength: 50,
                    error: 'Tên không hợp lệ'
                }),
                email: t.String({
                    format: 'email',
                    error: 'Email không hợp lệ'
                }),
                password: t.String({
                    minLength: 6,
                    maxLength: 50,
                    error: 'Mật khẩu không hợp lệ'
                })
            }),
            response: t.Object({
                status: t.Number(),
                message: t.String(),
                user: t.Object({
                    id: t.Any(),
                    name: t.String(),
                    email: t.String()
                })
            })
        }
    )


    .get('/verify', async ({ query, set }) => {
        const { token } = query;
        const user = await pool.query('SELECT * FROM users WHERE verification_token = $1', [token]);
        if (user.rows.length == 0) {
            set.status = 400;
            return {
                status: 400,
                message: 'Token không hợp lệ',
                user: { id: null, name: '', email: '' }
            };
        }
        // Đã có user, tiến hành xác thực
        await pool.query('UPDATE users SET is_verified = true WHERE verification_token = $1', [token]);
        set.status = 200;
        return {
            status: 200,
            message: 'Xác thực thành công',
            user: {
                id: user.rows[0].id,
                name: user.rows[0].name,
                email: user.rows[0].email
            }
        };
    },
        {
            response: t.Object({
                status: t.Number(),
                message: t.String(),
                user: t.Object({
                    id: t.Any(),
                    name: t.String(),
                    email: t.String()
                })
            })
        })

    .post('/login',
        async ({ body, set }) => {
            const { email, password } = body;

            // Kiểm tra xem email
            const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email])
            if (existing.rows.length == 0) {
                set.status = 400;
                return {
                    status: 400,
                    message: 'Email không tồn tại',
                    user: {
                        id: '',
                        name: ''
                    },
                    accessToken: '',
                    refreshToken: ''
                }
            }

            // Kiểm tra password
            const user = existing.rows[0];
            const isMatch = await bcryptjs.compare(password, user.password);
            if (!isMatch) {
                set.status = 400;
                return {
                    status: 400,
                    message: 'Mật khẩu không chính xác',
                    user: {
                        id: '',
                        name: ''
                    },
                    accessToken: '',
                    refreshToken: ''
                }
            }

            // Kiểm tra tài khoản đã được xác thực chưa
            const isVerified = user.is_verified;
            if (!isVerified) {
                set.status = 400;
                return {
                    status: 400,
                    message: 'Tài khoản chưa được xác thực',
                    user: {
                        id: '',
                        name: ''
                    },
                    accessToken: '',
                    refreshToken: ''
                }

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
                status: 200,
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
                email: t.String(),
                password: t.String()
            }),
            response: t.Object({
                status: t.Number(),
                message: t.String(),
                user: t.Object({
                    id: t.Any(),
                    name: t.String()
                }),
                accessToken: t.String(),
                refreshToken: t.String()
            })
        }

    )

    .post('/refresh-token',
        async ({ body, set }) => {
            const { refreshToken } = body;

            const user = await pool.query('SELECT * FROM refresh_tokens WHERE token = $1', [refreshToken]);

            if (user.rows.length == 0) {
                set.status = 400;
                return {
                    status: 400,
                    message: 'Refresh token không hợp lệ',
                    accessToken: ''
                }
            }
            const userId = user.rows[0].id;

            // Tạo access token mới
            const accessToken = jwt.sign({ id: userId }, process.env.JWT_SECRET as string, { expiresIn: '15m' });

            // Kiểm tra xem refresh token có hợp lệ không


            // Trả về access token mới
            set.status = 200;
            return {
                status: 200,
                message: 'Cấp lại access token thành công',
                accessToken
            }
        },
        {
            body: t.Object({
                refreshToken: t.String()
            }),
            response: t.Object({
                status: t.Number(),
                message: t.String(),
                accessToken: t.String()
            })

        }
    )

    .post('/forgot-password',
        async ({ body, set }) => {
            const { email } = body;
            const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
            if (user.rows.length == 0) {
                set.status = 400;
                return {
                    status: 400,
                    message: 'Email không tồn tại trong hệ thống',
                    user: {
                        email: email
                    }
                };
            }

            // Tạo và lưu token
            const verifyToken = jwt.sign({ email }, process.env.JWT_SECRET as string, { expiresIn: '10m' });
            await pool.query('UPDATE users SET verification_token = $1 WHERE email = $2', [verifyToken, email]);

            const verifyLink = `http://localhost:3000/auth/reset-password?token=${verifyToken}`;
            // Gửi email đặt lại mật khẩu
            await sendMails(email, verifyLink);
            set.status = 200;
            return {
                status: 200,
                message: 'Hãy kiểm tra gmail của bạn',
                user: {
                    email: email
                }
            }
        },
        {
            body: t.Object({
                email: t.String({
                    format: 'email',
                    error: 'Email không hợp lệ'
                })
            }),

            response: t.Object({
                status: t.Number(),
                message: t.String(),
                user: t.Object({
                    email: t.String()
                })
            })

        }
    )

    .post('/reset-password',
        async ({ body, set }) => {
            const { token, newPassword } = body;
            // Kiểm tra token
            let decoded;
            try {
                decoded = jwt.verify(token, process.env.JWT_SECRET as string) as { email?: string };
            } catch (err) {
                set.status = 400;
                return { status: 400, message: 'Token không hợp lệ hoặc đã hết hạn', newPassword: '' };
            }
            if (!decoded || !decoded.email) {
                set.status = 400;
                return { status: 400, message: 'Token không hợp lệ', newPassword: '' };
            }
            const hashedPassword = await bcryptjs.hash(newPassword, 10);
            // Cập nhật mật khẩu mới
            await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, decoded.email]);
            set.status = 200;
            return { status: 200, message: 'Đặt lại mật khẩu thành công', newPassword: hashedPassword };
        },
        {
            body: t.Object({
                token: t.String(),
                newPassword: t.String({
                    minLength: 6,
                    maxLength: 50,
                    error: 'Mật khẩu mới không hợp lệ'
                })
            }),

            response: t.Object({
                status: t.Number(),
                message: t.String(),
                newPassword: t.String()
            })
        }
    )

    // Thiết lập phía Client và Redirect URI từ Google
    .get('/google', () => {
        const query = qs.stringify({
            client_id: process.env.CLIENT_ID,
            redirect_uri: process.env.GOOGLE_REDIRECT_URI,
            response_type: 'code',
            scope: 'openid profile email',
            access_type: 'offline',
            prompt: 'consent'
        });
        return new Response(null, {
            status: 302,
            headers: {
                Location: `https://accounts.google.com/o/oauth2/auth?${query}`
            }
        });
    })

    .get('/google/callback', async ({ query, set }) => {
        const { code } = query;

        // Lấy access token từ Google
        const tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
            code,
            client_id: process.env.CLIENT_ID,
            client_secret: process.env.CLIENT_SECRET,
            redirect_uri: process.env.GOOGLE_REDIRECT_URI,
            grant_type: 'authorization_code'
        })

        const { access_token } = tokenRes.data;
        // Lấy thông tin người dùng từ Google
        const userRes = await axios.get('https://www.googleapis.com/oauth2/v1/userinfo', {
            headers: {
                Authorization: `Bearer ${access_token}`,
            },
        })

        const { email, name } = userRes.data;

        const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        let user;
        if (existing.rows.length == 0) {
            const insert = await pool.query(
                'INSERT INTO users (email, name, provider, is_verified) VALUES ($1, $2, $3, $4) RETURNING *',
                [email, name, 'google', true]
            );
            user = insert.rows[0];
        } else {
            user = existing.rows[0];
        }

        // Tạo và lưu access token và refresh token
        const accessToken = jwt.sign({ id: user.id }, process.env.ACCESS_SECRET as string, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ id: user.id }, process.env.ACCESS_SECRET as string, { expiresIn: '7d' });

        await pool.query(
            'INSERT INTO refresh_tokens (user_id, token) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET token = EXCLUDED.token RETURNING *',
            [user.id, refreshToken]
        );

        return {
            status: 200,
            message: 'Đăng nhập bằng Google thành công',
            user: user,
            accessToken: accessToken,
            refreshToken: refreshToken
        }

    },
        {

            response: t.Object({
                status: t.Number(),
                message: t.String(),
                user: t.String(),
                accessToken: t.String(),
                refreshToken: t.String()
            })
        }
    )


