import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { HealthCheckModule } from './health-check/health-check.module';

@Module({
  imports: [AuthModule, HealthCheckModule],
  controllers: [],
  providers: [],
})
export class AppModule {}
