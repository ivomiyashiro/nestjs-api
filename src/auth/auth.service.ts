import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import * as argon from 'argon2';
import { AuthDto } from './dto';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    // generate the psw hash
    const hash = await argon.hash(dto.password);
    // save user in db
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      delete user.hash;

      return user;
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }

      throw error;
    }
  }

  async singin(dto: AuthDto) {
    const ERROR = 'Email or password incorrect.';

    try {
      // find the user by email
      const user = await this.prisma.user.findFirstOrThrow({
        where: { email: dto.email },
      });

      // compare password
      const passwordMatch = await argon.verify(user.hash, dto.password);

      if (!passwordMatch) {
        throw new UnauthorizedException(ERROR);
      }

      delete user.hash;

      return user;
    } catch (error) {
      // if user does not exist throw exception
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2025') {
          throw new UnauthorizedException(ERROR);
        }
      }

      throw error;
    }
  }
}
