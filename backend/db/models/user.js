'use strict';
const {
  Model, Validator  //! needed to add Validator, getting error without it
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class User extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
    }
  }
  User.init({
    username: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        len: [4, 30],
        isNotEmail(value) {
          if (Validator.isEmail(value)) {
            throw new Error("Cannot be an email.")
          }
        },
      },
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        len: [3, 256],
        isEmail: true
      },
    },
    hashedPassword: {
      type: DataTypes.STRING.BINARY, //! not just a string but a "binary string"
      allowNull: false,
      validate: {
        len: [60, 60]
      },
    },
  }, {
    sequelize,
    modelName: 'User',
  });
  return User;
};