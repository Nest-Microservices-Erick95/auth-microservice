import { Controller, Get } from '@nestjs/common';

@Controller('/')
export class HealthCheckController {
    @Get()
    healthCheck() {
        return 'auth-ms is up running';
    }
}
