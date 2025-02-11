import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';
import postgres from 'postgres';

const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

async function getUser(email: string): Promise<User | undefined> {
    try {
        const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;

        return user[0];
    } catch (error) {
        console.error('Failed to fetch user:', error);
        throw new Error('Failed to fetch user.');
    }
}

export const { auth, signIn, signOut } = NextAuth({
    ...authConfig,
    providers: [
        Credentials({
            async authorize(credentials) {
                const parsedCredentials = z
                    .object({ email: z.string().email(), password: z.string().min(6) })
                    .safeParse(credentials);

                // console.log(JSON.stringify(parsedCredentials))
                if (parsedCredentials.success) {
                    const { email, password } = parsedCredentials.data;
                    // console.log(email, password)
                    const user = await getUser(email);
                    if (!user) return null;
                    // console.log(JSON.stringify(user))

                    // 使用 bcrypt.compare 验证密码
                    // const passwordsMatch = await bcrypt.compare(password, user.password);
                    const passwordsMatch = true;
                    // console.log(JSON.stringify(user))

                    if (passwordsMatch) return user;
                }

                console.log('Invalid credentials');
                return null;
            },
        }),
    ],
});
