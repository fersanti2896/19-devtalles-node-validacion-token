import { Router } from 'express';
import { AuthController } from './auth.controller';
import { AuthService, EmailService } from '../services';
import { envs } from '../../config/envs';

export class AuthRoutes {
  static get routes(): Router {
    const router = Router();

    const emailService = new EmailService(
      envs.MAILER_SERVICE,
      envs.MAILER_EMAIL,
      envs.MAILER_SECRET_KEY
    );
    
    const authService = new AuthService( emailService );
    const authController = new AuthController( authService );

    router.post( '/login', authController.loginUser );
    router.post( '/register', authController.register );

    router.get( '/validate-email/:token', authController.validateEmail );

    return router;
  }
}