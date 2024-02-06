package org.glebchanskiy.resourcer.models;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

@Data
@Document(collection = "keks2")
public class KekResource {
 @Id
 private String id;
 private String kekField;
}
