import * as passport from 'passport';
import { OAuth2Strategy as Strategy } from 'passport-facebook';

import User, { UserDocument } from './models/User';


const dev = process.env.NODE_ENV !== 'production';

function setupFacebook({ server }) {
  if (!process.env.FACEBOOK_APP_ID || !process.env.FACEBOOK_APP_SECRET) {
    return;
  }
  const verify = async (accessToken, refreshToken, profile, done) => {
    let email;
    let avatarUrl;

    if (profile.email) {
      email = profile.email;
    }

    if (profile.picture && profile.picture.length > 0) {
      avatarUrl = profile.picture.data.url;
    }

    try {
      const user = await User.signInOrSignUpViaFacebook({
        facebookId: profile.id,
        email,
        facebookToken: { accessToken, refreshToken },
        displayName: profile.name,
        avatarUrl,
      });

      done(null, user);
    } catch (err) {
      done(err);
      console.error(err);
    }
  };
  passport.use(new Strategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: `${dev ? process.env.URL_API : process.env.PRODUCTION_URL_API}/auth/facebook/callback`,
    profileFields: ['id', 'displayName', 'email', 'picture.type(large)']
  }, verify
  ));
  passport.serializeUser((user: UserDocument, done) => {
    done(null, user._id);
  });

  passport.deserializeUser((id, done) => {
    User.findById(id, User.publicFields()).exec((err, user) => {
      done(err, user);
    });
  });

  server.use(passport.initialize());
  server.use(passport.session());

  server.get('/auth/facebook',  passport.authenticate('facebook'));
  server.get('/auth/facebook/callback',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect .
      res.redirect(
        `${dev ? process.env.URL_APP : process.env.PRODUCTION_URL_APP}${redirectUrlAfterLogin}`,
      );
  });

}

export { setupFacebook };