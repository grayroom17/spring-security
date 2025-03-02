package guru.sfg.brewery.security;

import guru.sfg.brewery.domain.security.User;
import guru.sfg.brewery.repositories.security.UserRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;

@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@RequiredArgsConstructor
@Slf4j
@Service
public class UserUnlockService {

    UserRepository userRepository;

    @Scheduled(fixedRate = 300000)
    public void unlockAccounts() {
        log.debug("Running Unlock Accounts");

        List<User> lockedUsers =
                userRepository.findAllByAccountNonLockedAndLastModifiedDateBefore(
                        false,
                        Timestamp.valueOf(LocalDateTime.now().minusSeconds(30))
                );

        if (!lockedUsers.isEmpty()) {
            log.debug("Locked Accounts Found. Unlocking");
            lockedUsers.forEach(user -> user.setAccountNonLocked(true));

            userRepository.saveAll(lockedUsers);
        }
    }

}
