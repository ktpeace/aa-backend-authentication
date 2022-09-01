'use strict';
const bcrypt = require("bcryptjs");

module.exports = {
  async up (queryInterface, Sequelize) {
    await queryInterface.bulkInsert('Users', [
      {
      username: 'Lillian',
      email: 'lily@gmail.com',
      hashedPassword: bcrypt.hashSync('password')
    },
    {
      username: 'Leonard',
      email: 'justlilyshusband@gmail.com',
      hashedPassword: bcrypt.hashSync('password')
    }
  ], {})
  },

  async down (queryInterface, Sequelize) {
   const Op = Sequelize.Op;
   return queryInterface.bulkDelete('Users', {
      username: { [Op.in]: ['lily@gmail.com', 'Leonard'] }
    }, {});
  }
};
