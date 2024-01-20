import { JwtAdapter, bcryptAdapter } from '../../config';
import { UserModel } from '../../data';
import { CustomError, LoginUserDto, RegisterUserDto, UserEntity } from '../../domain';

export class AuthService {
    constructor() {}

    public async registerUser( registerUserDto: RegisterUserDto ) {
        const existUser = await UserModel.findOne({ email: registerUserDto.email });

        if( existUser ) throw CustomError.badRequest('Email already exist.');

        try {
            const user = new UserModel( registerUserDto );

            //* Encriptando la contraseña
            user.password = bcryptAdapter.hash( registerUserDto.password );

            await user.save();

            //* JWT
            const token = await JwtAdapter.generateToken({ id: user.id });

            if( !token ) throw CustomError.internalServer('Error while creating JWT.');
            
            //* Email de confirmación

            const { password, ...userEntity } = UserEntity.fromObject( user );

            return { 
                user: userEntity,
                token
            };
        } catch (error) {
            throw CustomError.internalServer(`${ error }`);
        }
    } 

    public async loginUser( loginUserDto: LoginUserDto ) {
        const existUser = await UserModel.findOne({ email: loginUserDto.email });

        if( !existUser ) throw CustomError.badRequest('User not exists.');

        try {
            const validPassword = bcryptAdapter.compare( loginUserDto.password, existUser.password );

            if( !validPassword ) throw CustomError.badRequest('Password incorrect.')

            const { password, ...userEntity } = UserEntity.fromObject( existUser );
            const token = await JwtAdapter.generateToken({ id: existUser.id });

            if( !token ) throw CustomError.internalServer('Error while creating JWT.');

            return {
                user: userEntity,
                token
            }
        } catch (error) {
            throw CustomError.internalServer(`${ error }`);
        }
    }
}