package verification.registration.token;

import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class ConfirmationService {

    private final ConfirmationRepo confirmationRepo;

    public ConfirmationService(ConfirmationRepo confirmationRepo) {
        this.confirmationRepo = confirmationRepo;
    }

    public void saveConfirmationToken(ConfirmationToken token) {
        confirmationRepo.save(token);
    }

    public Optional<ConfirmationToken> getToken(String token) {
       return confirmationRepo.findByToken(token);
    }

    public int setConfirmedAt(String token) {
        return confirmationRepo.updateConfirmedAt(token, LocalDateTime.now());
    }
}
