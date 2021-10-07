package verification.appuser;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import verification.registration.token.ConfirmationService;
import verification.registration.token.ConfirmationToken;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class AppUserService implements UserDetailsService {

    private final static String USER_NOT_FOUND_MSG = "user with email %s not found";
    private final UserRepo userRepo;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationService confirmationService;

   public AppUserService(UserRepo userRepo, BCryptPasswordEncoder bCryptPasswordEncoder, ConfirmationService confirmationService) {
       this.userRepo = userRepo;
       this.bCryptPasswordEncoder = bCryptPasswordEncoder;
       this.confirmationService = confirmationService;
   }



    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
       return userRepo.findByEmail(email).orElseThrow(()-> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, email)));
    }

    public String signUpUser(AppUser appUser) {

       boolean userExist = userRepo.findByEmail(appUser.getEmail())
               .isPresent();

       if (userExist) {
           throw new IllegalStateException("email already taken");
       }

       String encodedPassword = bCryptPasswordEncoder.encode(appUser.getPassword());
       appUser.setPassword(encodedPassword);

       userRepo.save(appUser);

        String token = UUID.randomUUID().toString();
       // send confirmation token
        ConfirmationToken confirmationToken = new ConfirmationToken(
            token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                appUser
        );

        confirmationService.saveConfirmationToken(confirmationToken);

        // send email
       return token;
    }

    public int enableAppUser(String email) {
       return userRepo.enableAppUser(email);
    }
}
