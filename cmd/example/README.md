Example
=======

This example demonstates how to use authgo to implement a website with authentication where product listings can only be accessed by signed in customers.

# Routes

- / - This is the home page.
- /account - Customer account page.
- /account-password - Allows a registered customer to change their password.
- /account-recovery - Allows a registered customer to recover their account.
- /sign-in - Allows registered customer to sign in.
- /sign-out - Allows signed in customers to sign out.
- /sign-up - Provides a form for new customers to register and create an account by providing their email address, and selecting a username and password.
- /sign-up-verification - Allows new customers to verify their email address by entering the one-time code that was sent to it.
- /health - Enables other servers (such as a load balancer) to monitor this server.
- /products - Lists all products.
- /product?id={id} - Shows the product with the given ID.
- /static/ - Holds various assets such as Stylesheets, Terms of Service, and Privacy Policy.
