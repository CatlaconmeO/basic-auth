import nodemailer from 'nodemailer';
import { pool } from '../db/db';

export const sendMails = async (email: string, verifyLink: string) => {
    // Gửi email xác thực
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_PASS,
        },
    });

    // Nội dung email
    const mailOptions = {
        from: process.env.GMAIL_USER,
        to: email,
        subject: 'Xác thực tài khoản',
        text: 'Vui lòng nhấp vào liên kết sau để xác thực tài khoản của bạn: ' + verifyLink,
    };

    //Gửi email
    try {
        await transporter.sendMail(mailOptions);
        return { status: 200, message: 'Hãy kiểm tra email để xác thực tài khoản, link xác thực sẽ có hiệu lực trong 10 phút' };
    } catch (error) {
        // Xoá user sau khi gửi mail thất bại
        // await pool.query('DELETE FROM users WHERE email = $1', [email]);
        return { status: 500, message: 'Gửi email thất bại' };
    }
}