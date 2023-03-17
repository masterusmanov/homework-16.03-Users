import { Column, DataType, Model, Table, HasMany } from "sequelize-typescript";

interface UsersCreationAttrs{
    first_name: string;
    last_name: string;
    username: string;
    hashed_password: string;
    email: string;
    phone: string;
    is_owner: boolean;
    Is_active: boolean;
    hashed_refresh_token: string;

};

@Table({tableName: 'users'})
export class Users extends Model<Users, UsersCreationAttrs> {
    @Column({
        type: DataType.INTEGER,
        autoIncrement: true,
        primaryKey: true
    })
    id: number;

    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    first_name: string;

    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    last_name: string;

    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    username: string;

    @Column({
        type: DataType.STRING,
    })
    hashed_password: string;
    
    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    email: string;
    
    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    phone: string;

    @Column({
        type: DataType.BOOLEAN,
        defaultValue: false
    })
    is_owner: boolean;

    @Column({
        type: DataType.BOOLEAN,
        defaultValue: false

    })
    is_active: boolean;

    @Column({
        type: DataType.STRING,
    })
    hashed_refresh_token: string;

    
    @Column({
        type: DataType.STRING,
    })
    activation_link: string;

}
