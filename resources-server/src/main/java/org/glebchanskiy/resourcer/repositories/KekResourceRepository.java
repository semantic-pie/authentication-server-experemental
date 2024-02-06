package org.glebchanskiy.resourcer.repositories;

import org.glebchanskiy.resourcer.models.KekResource;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface KekResourceRepository extends CrudRepository<KekResource, String> {
}