import { redisClient } from '../utils/redisClient';

const WINDOW_SIZE_IN_SECONDS = 60; // 1 phút
const MAX_REQUESTS = 5;

export const rateLimiter = async (context: any) => {
    const ip = context.request.headers['x-forwarded-for'] 
    || context.request.headers['x-real-ip'] 
    || context.request.ip 
    || 'unknown';

    // Cài đặt khoá trong Redis cho từng IP
    const key = `rate_limit:${ip}`;

    // Kết nối redis nếu chưa kết nối
    if (!redisClient.isOpen) await redisClient.connect();

    // Lấy key để đếm số request
    let reqCount = await redisClient.get(key);

    // Xử lý số lượng request
    if (reqCount === null) {
        await redisClient.set(key, '1', { EX: WINDOW_SIZE_IN_SECONDS });
    } else if (parseInt(reqCount) < MAX_REQUESTS) {
        await redisClient.incr(key);
    } else {
        return new Response('Too many requests, please try again later.', { status: 429 });
    }
};
