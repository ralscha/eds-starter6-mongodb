package ch.rasc.eds.starter.util;

import java.util.ArrayList;
import java.util.List;

import org.bson.conversions.Bson;

import com.mongodb.client.model.Sorts;

import ch.ralscha.extdirectspring.bean.ExtDirectStoreReadRequest;
import ch.ralscha.extdirectspring.bean.SortDirection;
import ch.ralscha.extdirectspring.bean.SortInfo;

public abstract class QueryUtil {

	public static List<Bson> getSorts(ExtDirectStoreReadRequest request) {
		List<Bson> sorts = new ArrayList<>();
		for (SortInfo sortInfo : request.getSorters()) {

			if (sortInfo.getDirection() == SortDirection.ASCENDING) {
				sorts.add(Sorts.ascending(sortInfo.getProperty()));
			}
			else {
				sorts.add(Sorts.descending(sortInfo.getProperty()));
			}
		}
		return sorts;
	}

}