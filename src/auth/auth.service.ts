import { Injectable, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { RegisterUserDto } from './dto/register-user.dto';

import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config/envs';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    
    constructor(
        private readonly jwtService: JwtService
    ) {
        super()
    }

    onModuleInit() {
        this.$connect();
    }


    async signJWT(payload: JwtPayload) {
        return this.jwtService.sign(payload);
    }


    async registerUser(registerUserDto: RegisterUserDto) {
        const { email, name, password } = registerUserDto;
        
        try {
            const user = await this.user.findUnique({
                where: { email }
            });

            if(user) {
                throw new RpcException({
                    status: 400,
                    message: 'user already exists'
                });
            }

            const newUser = await this.user.create({
                data: {
                    email,
                    password: bcrypt.hashSync(password, 10),
                    name
                }
            });

            const { password: _, ...rest } = newUser;

            return {
                user: rest,
                token: await this.signJWT(rest)
            };
        } catch(error) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    }

    async loginUser(loginUserDto: LoginUserDto) {
        const { email, password } = loginUserDto;
        
        try {
            const user = await this.user.findUnique({
                where: { email }
            });

            if(!user) {
                throw new RpcException({
                    status: 400,
                    message: 'user/password not valid'
                });
            }

            const isPasswordValid = bcrypt.compareSync(password, user.password);
            if(!isPasswordValid) {
                throw new RpcException({
                    status: 400,
                    message: 'user/password not valid'
                });
            }

            const { password: _, ...rest } = user;

            return {
                user: rest,
                token: await this.signJWT(rest)
            };
        } catch(error) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    }

    async verifyToken(token: string) {
        try {
            const { sub, iat, exp, ...user } = this.jwtService.verify(token, { 
                secret: envs.jwtSecret
            });
            return {
                user,
                token: await this.signJWT(user)
            };
        } catch(error) {
            throw new RpcException({
                status: 401,
                message: 'Invalid token'
            });
        }
    }
}
